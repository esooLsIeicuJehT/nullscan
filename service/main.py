"""
service.main — HTTP transport. Thin by mandate.

This module is allowed to: parse requests, enforce limits, call the dispatcher,
serialise responses. It is NOT allowed to contain analysis logic. If you ever
find yourself importing `struct` in here, the boundary has been breached.

WHAT CHANGED FROM THE ORIGINAL SKETCH
-------------------------------------
1. `@app.get('/api-scan/')` with `data: dict`
   A GET cannot reliably carry a JSON body. FastAPI treats a bare `dict`
   parameter as a *body* parameter, so this route compiles, generates a broken
   OpenAPI schema, and then 422s for every real client (requests, httpx, curl
   and fetch all refuse to attach a body to GET by default). Now POST.

2. `await extract_and_analyze(file)` inside the handler
   CPU-bound work on the event loop. See service/jobs.py. Now 202 + poll.

3. `UploadFile` read without a size cap
   `file.read()` on a 4 GB upload is an OOM kill. Now streamed to disk with a
   hard byte ceiling and Content-Length is never trusted.

4. `-> Dict[str, str]`
   The payload is nested and polymorphic. Now Pydantic response models, which
   double as the published API contract.

5. No core/transport boundary
   Analysis lived inside the web app. Now `core/` is import-clean of FastAPI
   and ships as a CLI and a wheel from the same source.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import re
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import (
    Depends,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
    status,
)
from fastapi.responses import FileResponse, JSONResponse

from core import ENGINE_VERSION, SCHEMA_VERSION, build_sbom, diff_reports

from . import mailer
from .billing import (
    TIERS,
    BillingStore,
    StripeError,
    apply_event,
    create_checkout_session,
    create_portal_session,
    verify_webhook,
)
from .config import settings
from .jobs import Dispatcher
from .public import PublicStore, client_principal, valid_email
from .schemas import (
    AccountOut,
    CheckoutIn,
    CheckoutOut,
    DiffRequest,
    DriftOut,
    ErrorOut,
    JobOut,
    QuotaOut,
    RecoverIn,
    RecoverOut,
    SubmitAccepted,
    TierOut,
    WaitlistIn,
    WaitlistOut,
)
from .security import bind_key_store, require_api_key, verify_signature
from .store import JobStore

_HEX64 = re.compile(r"[0-9a-fA-F]{64}")

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
log = logging.getLogger("nullscan")

store = JobStore(settings.db_path)
public = PublicStore(settings.db_path)
billing = BillingStore(settings.db_path)
bind_key_store(billing)
dispatcher = Dispatcher(store)
WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

CHUNK = 1024 * 1024


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    os.makedirs(settings.upload_dir, exist_ok=True)
    dispatcher.start()
    purged = store.purge_older_than(settings.retain_hours)
    if purged:
        log.info("purged %d expired job(s)", purged)
    public.purge_quota(settings.free_window_s)

    # Anything here is a person who has been charged and received nothing.
    # We cannot re-send the original key (we only hold its hash), so the sweep
    # reports rather than retries — the operator rotates from the account page
    # or the customer uses recovery. Silence would be worse than a loud log.
    stuck = billing.undelivered()
    if stuck:
        log.error("%d PAID KEY(S) NEVER DELIVERED — customers charged with "
                  "nothing to show for it: %s", len(stuck),
                  ", ".join(f"{r['key_fp']}({r['delivery_attempts']} attempts)"
                            for r in stuck[:10]))
    yield
    dispatcher.shutdown()


app = FastAPI(
    title="NULLSCAN",
    version=ENGINE_VERSION,
    description="Android compliance scanner: Play Data Safety declaration "
                "generation and build-over-build compliance drift.",
    lifespan=lifespan,
)


# --- helpers -----------------------------------------------------------------
async def _spool_upload(file: UploadFile) -> tuple[str, int]:
    """Stream to disk with a hard ceiling. Never trusts Content-Length."""
    dest = os.path.join(settings.upload_dir, f"{uuid.uuid4().hex}.apk")
    written = 0
    try:
        with open(dest, "wb") as out:
            while chunk := await file.read(CHUNK):
                written += len(chunk)
                if written > settings.max_upload_bytes:
                    raise HTTPException(
                        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        f"upload exceeds {settings.max_upload_bytes // (1024*1024)} MB",
                    )
                out.write(chunk)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(dest)
        raise
    if written == 0:
        os.unlink(dest)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "empty upload")
    return dest, written


def _principal(request: Request, api_key: str | None) -> str:
    return client_principal(
        api_key=api_key,
        peer=request.client.host if request.client else None,
        forwarded_for=request.headers.get("x-forwarded-for"),
        trust_proxy=settings.trust_proxy,
    )


_MONTH_S = 30 * 86_400


def _mask(email: str | None) -> str | None:
    """j****a@ghostdroid.dev — enough to recognise your own address, not enough
    to be worth harvesting if a key ever leaks."""
    if not email or "@" not in email:
        return None
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        return f"{local[0]}*@{domain}"
    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"


def _limit_for(api_key: str | None) -> tuple[int, int]:
    """(limit, window_seconds). -1 means unmetered."""
    if api_key is None:
        return settings.free_scans, settings.free_window_s
    row = billing.lookup(api_key)
    if row is None:
        return -1, _MONTH_S            # env-var key, legacy unmetered
    tier = TIERS.get(row["tier"])
    return (tier.monthly_scans if tier else -1), _MONTH_S


def _sha_of(path: str) -> str:
    import hashlib

    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while c := fh.read(CHUNK):
            h.update(c)
    return h.hexdigest()


# --- routes ------------------------------------------------------------------
@app.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    return {"status": "ok", "engine": ENGINE_VERSION, "schema": SCHEMA_VERSION}


@app.post(
    "/v1/scans",
    response_model=SubmitAccepted,
    status_code=status.HTTP_202_ACCEPTED,
    responses={413: {"model": ErrorOut}, 400: {"model": ErrorOut}},
    summary="Submit an APK for analysis",
)
async def submit_scan(
    request: Request,
    response: Response,
    file: Annotated[UploadFile, File(description="APK or AAB")],
    api_key: Annotated[str | None, Depends(require_api_key)] = None,
    force: Annotated[bool, Query(description="Bypass the SHA-256 result cache")] = False,
    sha256: Annotated[str | None, Query(
        description="Optional SHA-256 of the file. If we already have a report "
                    "for it, you get it back with no upload and no quota charge."
    )] = None,
) -> SubmitAccepted:
    principal = _principal(request, api_key)
    limit, window = _limit_for(api_key)
    metered = limit >= 0

    # A cache hit costs no CPU, so it should cost no quota — but we cannot know
    # it IS a hit until the file is hashed, and hashing needs the upload. That
    # ordering conflict is resolved by letting the caller send the digest ahead
    # of the bytes: CI already has it, and it turns a 120 MB re-upload into a
    # 200-byte request. Browsers don't send it and simply get the normal path.
    if sha256 and not force and _HEX64.fullmatch(sha256):
        hinted = store.find_report_by_sha(sha256.lower())
        if hinted is not None:
            job_id = store.create(file.filename or "upload.apk", api_key)
            store.finish(job_id, hinted)
            response.status_code = status.HTTP_200_OK
            return SubmitAccepted(job_id=job_id, state="done",
                                  poll_url=f"/v1/scans/{job_id}", cached=True)

    # Check the quota BEFORE spooling. Streaming 500 MB to disk and then
    # refusing is free bandwidth for an abuser and a slow error for everyone.
    if metered and public.used(principal, window) >= limit:
        wait = public.next_reset(principal, window)
        plan = f"Free tier is {limit} scans per day" if api_key is None \
            else f"Your plan allows {limit} scans per month"
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"{plan}. Resets in {wait // 3600}h {(wait % 3600) // 60}m. "
            f"Send ?sha256= to re-fetch a build you already scanned, free.",
        )

    path, _size = await _spool_upload(file)

    # Content-addressed cache. Re-uploading an unchanged build in CI is the
    # single most common request pattern; serving it from cache costs nothing
    # and is what keeps unit economics positive on the free tier.
    sha = _sha_of(path)
    if not force:
        cached = store.find_report_by_sha(sha)
        if cached is not None:
            os.unlink(path)
            job_id = store.create(file.filename or "upload.apk", api_key)
            store.finish(job_id, cached)
            response.status_code = status.HTTP_200_OK
            # Reached only when quota was already available: no charge is taken
            # below, so an unhinted cache hit is free too.
            return SubmitAccepted(
                job_id=job_id, state="done",
                poll_url=f"/v1/scans/{job_id}", cached=True,
            )

    job_id = store.create(file.filename or "upload.apk", api_key)
    if metered:
        public.charge(principal)
    dispatcher.submit(job_id, path)
    return SubmitAccepted(
        job_id=job_id, state="queued", poll_url=f"/v1/scans/{job_id}", cached=False
    )


@app.get(
    "/v1/scans/{job_id}",
    response_model=JobOut,
    responses={404: {"model": ErrorOut}},
    summary="Poll a scan",
)
async def get_scan(
    job_id: str,
    _api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> JobOut:
    job = store.get(job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown job_id")
    return JobOut(**job)


@app.get(
    "/v1/scans/{job_id}/declaration",
    summary="Play Data Safety declaration only",
    response_model=list[dict[str, Any]],
)
async def get_declaration(
    job_id: str,
    _api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> list[dict[str, Any]]:
    job = store.get(job_id)
    if job is None or not job.get("report"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no completed report for that id")
    return job["report"]["declaration"]


@app.get("/v1/scans/{job_id}/sbom", summary="CycloneDX 1.5 SBOM")
async def get_sbom(
    job_id: str,
    _api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> dict[str, Any]:
    job = store.get(job_id)
    if job is None or not job.get("report"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no completed report for that id")
    return build_sbom(job["report"])


@app.post(
    "/v1/diff",
    response_model=DriftOut,
    dependencies=[Depends(verify_signature)],
    summary="Compliance drift between two builds",
    description="Accepts job ids or inline reports. POST because it takes a body — "
                "the original GET form could not.",
)
async def post_diff(
    payload: DiffRequest,
    _request: Request,
    _api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> DriftOut:
    def resolve(job_id: str | None, inline: dict[str, Any] | None, label: str) -> dict[str, Any]:
        if inline is not None:
            return inline
        if job_id is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                f"provide {label}_job_id or {label}_report")
        job = store.get(job_id)
        if job is None or not job.get("report"):
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"{label} job has no completed report")
        return job["report"]

    base = resolve(payload.base_job_id, payload.base_report, "base")
    head = resolve(payload.head_job_id, payload.head_report, "head")
    return DriftOut(**diff_reports(base, head).to_dict())


@app.get("/v1/scans", response_model=list[dict[str, Any]], summary="Recent scans")
async def list_scans(
    api_key: Annotated[str | None, Depends(require_api_key)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
) -> list[dict[str, Any]]:
    return store.latest_for_key(api_key, limit)


@app.get("/v1/quota", response_model=QuotaOut, summary="Remaining free scans")
async def get_quota(
    request: Request,
    api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> QuotaOut:
    if api_key:
        row = billing.lookup(api_key)
        tier = TIERS.get(row["tier"]) if row else None
        if tier is None:
            # env-var key: legacy, unmetered, no subscription behind it
            return QuotaOut(limit=-1, used=0, remaining=-1, resets_in_s=0,
                            metered=False, tier="unlimited")
        p = _principal(request, api_key)
        used = public.used(p, _MONTH_S)
        return QuotaOut(
            limit=tier.monthly_scans, used=used,
            remaining=max(0, tier.monthly_scans - used),
            resets_in_s=public.next_reset(p, _MONTH_S),
            metered=True, tier=tier.slug,
        )
    p = _principal(request, api_key)
    used = public.used(p, settings.free_window_s)
    return QuotaOut(
        limit=settings.free_scans,
        used=used,
        remaining=max(0, settings.free_scans - used),
        resets_in_s=public.next_reset(p, settings.free_window_s),
        metered=True, tier="free",
    )


@app.post("/v1/waitlist", response_model=WaitlistOut, summary="Join build-tracking early access")
async def join_waitlist(payload: WaitlistIn) -> WaitlistOut:
    if not valid_email(payload.email):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "That address does not look right.")
    added = public.add_email(payload.email, payload.source or "web")
    return WaitlistOut(email=payload.email.strip().lower(), added=added)


@app.get("/v1/plans", response_model=list[TierOut], summary="Pricing")
async def plans() -> list[TierOut]:
    return [
        TierOut(slug=t.slug, name=t.name, price_cents=t.price_cents,
                monthly_scans=t.monthly_scans, blurb=t.blurb)
        for t in TIERS.values()
    ]


@app.post("/v1/checkout", response_model=CheckoutOut, summary="Start a subscription")
async def checkout(payload: CheckoutIn) -> CheckoutOut:
    # Validate input BEFORE checking configuration. A typo'd plan name is a
    # client error whether or not Stripe is wired up; returning 503 for it
    # tells the caller "try again later" about something that will never work.
    tier = TIERS.get(payload.tier)
    if tier is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            f"Unknown plan. Choose one of: {', '.join(TIERS)}")
    if not settings.stripe_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Billing is not configured on this instance.")
    base = settings.public_url.rstrip("/")
    try:
        # Network call in a worker thread: urllib is blocking and this handler
        # runs on the event loop.
        session = await asyncio.to_thread(
            create_checkout_session,
            secret_key=settings.stripe_secret, tier=tier,
            success_url=f"{base}/?checkout=success",
            cancel_url=f"{base}/?checkout=cancelled",
            email=payload.email,
        )
    except StripeError as exc:
        log.error("checkout failed: %s", exc)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            "Could not reach the payment provider.") from exc
    return CheckoutOut(url=session["url"], session_id=session.get("id", ""))


@app.post("/v1/billing-portal", summary="Manage an existing subscription")
async def billing_portal(
    api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> dict[str, str]:
    if not settings.stripe_secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Billing is not configured on this instance.")
    row = billing.lookup(api_key or "")
    if row is None or not row.get("customer_id"):
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "No subscription is attached to that key.")
    try:
        s = await asyncio.to_thread(
            create_portal_session, secret_key=settings.stripe_secret,
            customer_id=row["customer_id"],
            return_url=settings.public_url.rstrip("/") + "/",
        )
    except StripeError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            "Could not reach the payment provider.") from exc
    return {"url": s["url"]}


@app.post("/v1/stripe/webhook", include_in_schema=False)
async def stripe_webhook(request: Request) -> JSONResponse:
    raw = await request.body()
    try:
        event = verify_webhook(raw, request.headers.get("stripe-signature", ""),
                               settings.stripe_webhook_secret)
    except StripeError as exc:
        # 400, never 500: a 5xx makes Stripe retry a request that will never
        # succeed, and the event ends up in their dead-letter queue.
        log.warning("rejected webhook: %s", exc)
        return JSONResponse({"error": str(exc)}, status_code=400)

    result = apply_event(event, billing)
    if result.get("action") == "key_issued":
        # Fingerprint only. Logs are copied into error trackers, hosting
        # dashboards, backups and support tickets — a raw key here undoes the
        # hashing at rest entirely, because the plaintext just lives somewhere
        # else instead.
        log.warning("PROVISIONED tier=%s customer=%s key_fp=%s",
                    result["tier"],
                    (event.get("data") or {}).get("object", {}).get("customer", "?"),
                    result.get("key_fp", "?"))
        tier_obj = TIERS.get(result["tier"])
        if result.get("email"):
            subject, body = mailer.key_delivery(
                key=result["key"],
                tier_name=tier_obj.name if tier_obj else result["tier"],
                monthly_scans=tier_obj.monthly_scans if tier_obj else 0,
                base_url=settings.public_url.rstrip("/"),
            )
            # Deliberately not awaited into the response path and never raised:
            # the key is already provisioned, and a mail failure that 500s here
            # makes Stripe retry, which hits the idempotency guard and issues
            # nothing — leaving a paying customer with no key and no error.
            delivered = await asyncio.to_thread(
                mailer.send, api_key=settings.resend_api_key,
                sender=settings.mail_from, to=result["email"],
                subject=subject, text=body,
            )
            billing.mark_delivery(result["key_hash"],
                                  "sent" if delivered else "failed",
                                  "" if delivered else "mailer rejected the send")
            if not delivered:
                # No raw key in the log. The startup sweep retries it, and if
                # mail is genuinely broken the fingerprint identifies the row
                # without exposing the credential.
                log.error("KEY NOT DELIVERED key_fp=%s to=%s — queued for retry",
                          result.get("key_fp"), result["email"])
        if result.get("email_missing"):
            log.error(
                "NO EMAIL on session %s. This key cannot be delivered and the "
                "customer cannot be identified if they lose it. Recover it from "
                "Stripe: customer %s",
                (event.get("data") or {}).get("object", {}).get("id", "?"),
                (event.get("data") or {}).get("object", {}).get("customer", "?"),
            )
    return JSONResponse({"received": True, **{k: v for k, v in result.items()
                                              if k != "key"}})


@app.post("/v1/keys/recover", response_model=RecoverOut,
          summary="Re-send an API key to the address that paid")
async def recover_key(request: Request, payload: RecoverIn) -> RecoverOut:
    # Same answer either way. Branching on whether the address exists turns
    # this into a customer-list oracle: anyone could probe addresses to learn
    # who pays for the product.
    generic = RecoverOut(
        sent=True,
        message="If that address has an active subscription, the key is on its way.",
    )

    if not valid_email(payload.email):
        return generic

    # Rate limit on the ADDRESS, not the IP. Limiting by IP lets one attacker
    # spread a mail-bomb across proxies; limiting by address caps how many
    # messages any one inbox can be made to receive, which is the actual harm.
    bucket = f"recover:{payload.email.strip().lower()}"
    if public.used(bucket, 86_400) >= settings.recover_per_day:
        return generic
    public.charge(bucket)

    rotated = billing.rotate_for_email(payload.email)
    if rotated is None:
        return generic
    new_key, tier_slug = rotated

    tier = TIERS.get(tier_slug)
    subject, body = mailer.key_recovery(
        key=new_key, tier_name=tier.name if tier else tier_slug,
        base_url=settings.public_url.rstrip("/"),
    )
    await asyncio.to_thread(
        mailer.send, api_key=settings.resend_api_key, sender=settings.mail_from,
        to=payload.email.strip().lower(), subject=subject, text=body,
    )
    log.info("ROTATED key for a recovery request (email withheld from logs)")
    return generic


@app.get("/v1/account", response_model=AccountOut, summary="Your plan and usage")
async def account(
    request: Request,
    api_key: Annotated[str | None, Depends(require_api_key)] = None,
) -> AccountOut:
    if not api_key:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This endpoint needs an API key.")
    row = billing.lookup(api_key)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "No subscription for that key.")
    tier = TIERS.get(row["tier"])
    limit = tier.monthly_scans if tier else -1
    used = public.used(_principal(request, api_key), _MONTH_S)
    return AccountOut(
        tier=row["tier"], status=row["status"],
        email_masked=_mask(row.get("email")),
        limit=limit, used=used,
        remaining=(max(0, limit - used) if limit >= 0 else -1),
        resets_in_s=public.next_reset(_principal(request, api_key), _MONTH_S),
    )


@app.exception_handler(HTTPException)
async def http_error(_: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorOut(error=str(exc.detail)).model_dump(),
    )


if settings.serve_web:
    @app.get("/", include_in_schema=False)
    async def index() -> Response:
        page = os.path.join(WEB_DIR, "index.html")
        if not os.path.exists(page):
            return JSONResponse({"error": "web/index.html not found"}, status_code=404)
        # no-store: the page embeds no state, but a cached shell against a
        # redeployed API is a support ticket nobody can reproduce.
        return FileResponse(page, media_type="text/html",
                            headers={"Cache-Control": "no-store"})


# Kept only so old clients get a useful 410 instead of a confusing 404.
@app.post("/upload-apk/", include_in_schema=False)
async def legacy_upload() -> Response:
    return JSONResponse(
        status_code=status.HTTP_410_GONE,
        content={"error": "moved", "detail": "POST /v1/scans, then poll /v1/scans/{job_id}"},
    )
