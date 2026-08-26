# NULLSCAN — quickstart

## 0. What needs installing (read this before pip)

| You want to... | Install |
|---|---|
| Scan APKs, run the harness, run the CLI | **nothing** — bare Python 3 |
| Run the HTTP API | `pip install -r requirements.txt` |

`core/`, `cli.py`, `tools/harvest.py` and `tests/test_engine.py` import **zero**
third-party packages. Verified, not assumed — 13 files, stdlib only.

### On Termux: do NOT run `pip install -r requirements.txt`

It will fail. `pydantic-core` is Rust, and there is no prebuilt wheel for
`aarch64-linux-android`, so pip tries to compile it and dies on
`Target triple not supported by rustup`.

You don't need it. Skip straight to step 2.

If you later want the API running on-device, you'd need `pkg install rust
binutils` and a 20–40 minute compile. Not worth it — run the API on the Fedora
box and use the phone only for corpus work.

## 1. Prove it still works

```bash
# stdlib only — works anywhere, including Termux
python3 $HOME/nullscan/tests/test_engine.py     # expect 48 passed

# needs fastapi + pydantic — desktop only
python3 /home/jigga/nullscan/tests/test_service.py   # expect 32 passed
```

Both run standalone. No pytest needed.

## 2. Validate against real APKs — DO THIS BEFORE ANYTHING ELSE

### Option A — entirely on your phone, in Termux (no adb, no root, no cable)

```bash
pkg install python
cd $HOME && unzip nullscan.zip
# no pip install — none needed

bash $HOME/nullscan/tools/pull_corpus_termux.sh $HOME/apk-corpus 40 150

python3 $HOME/nullscan/tools/harvest.py $HOME/apk-corpus \
        --out $HOME/apk-corpus-results --jobs 1
```

`core/` is stdlib only, so the harness runs on a bare Termux Python with
nothing installed.

**Expect the pull step to fail on Android 11+.** `cmd package` is refused for
normal app UIDs — Termux is not the shell user — and you get:

```
cmd: Failure calling service package: Failed transaction (2147483646)
```

That is not fixable from inside Termux. The script detects it and prints the
fallbacks. Use wireless debugging, which still needs no PC:

```bash
pkg install android-tools
bash $HOME/nullscan/tools/adb_wireless.sh
```

That script walks you through pairing and then offers to pull the corpus.
It exists because the usual instructions are written as
`adb pair 127.0.0.1:<PAIRING_PORT>` — and in zsh, `<PAIRING_PORT>` is an input
redirection from a file that doesn't exist, so the whole paste dies with
`parse error near \n'`. The angle-bracket placeholder IS the bug. The script
prompts for the numbers instead, and validates them.

Two ports, and they are different numbers:

| | Where | Looks like |
|---|---|---|
| **PAIRING port** + 6-digit code | in the popup after "Pair device with pairing code" | `41234` + `668417` |
| **CONNECT port** | main Wireless debugging screen, under the IP | `40307` |

Both change every time you toggle Wireless debugging off and on. adb then runs
as the shell UID and sees every package.

**Third option, no debugging at all:** download 20–30 APKs in your browser and
point the harness at the folder — it walks any directory.

```bash
termux-setup-storage
python3 $HOME/nullscan/tools/harvest.py ~/storage/downloads \
        --out $HOME/apk-corpus-results --jobs 1
```

Prefer APKMirror over F-Droid. F-Droid builds are open source and carry almost
no ad or analytics SDKs — the exact thing you're trying to test detection
against, so they'd give you a falsely clean result.

### Option B — desktop, phone on USB

```bash
bash /home/jigga/nullscan/tools/pull_corpus.sh /home/jigga/apk-corpus 40

python3 /home/jigga/nullscan/tools/harvest.py /home/jigga/apk-corpus \
        --out /home/jigga/apk-corpus-results
```

### About split APKs

Most Play-delivered apps are split bundles. Both scripts take **base.apk only**,
on purpose: it carries `AndroidManifest.xml` and the primary dex, which is
everything the scanner reads. Config splits hold resources and native libs, so
`native_count` will read 0 for those apps in the harvest. Corpus artefact, not
an engine bug — don't chase it.

Read `/home/jigga/apk-corpus-results/HARVEST.md` first. It opens with a ship
gate: **PASS** or **HOLD**.

Everything above was proven against synthetic APKs built from the format spec.
That proves the byte offsets are right. It does not prove the engine survives
an 80 MB R8-obfuscated app with six dex files. Nothing you can reason about
tells you that — you have to run it.

## 3. Scan one APK

```bash
python3 /home/jigga/nullscan/cli.py scan /home/jigga/apk-corpus/com.example.app.apk
python3 /home/jigga/nullscan/cli.py scan /path/to/app.apk --json > report.json
```

## 4. Diff two builds (the CI gate)

```bash
python3 /home/jigga/nullscan/cli.py diff baseline.json candidate.apk --fail-on-drift
```

Exit code 1 when the new build would make a previously-accurate Play Data
Safety form wrong, or adds a high-severity finding.

## 5. Run the API

```bash
cd /home/jigga/nullscan
uvicorn service.main:app --reload --port 8000
```

Docs at http://localhost:8000/docs

```bash
curl -sX POST http://localhost:8000/v1/scans -F file=@app.apk
curl -s http://localhost:8000/v1/scans/<job_id>
curl -s http://localhost:8000/v1/scans/<job_id>/declaration
```

## 5a. Run the scanner UI on Termux (no dependencies)

`uvicorn` needs FastAPI, FastAPI needs pydantic, pydantic-core is Rust with no
aarch64-linux-android wheel. On Termux that install compiles for 30+ minutes
and usually fails. So there's a stdlib-only dev server:

```bash
python3 $HOME/nullscan/tools/serve_local.py
# then open http://localhost:8000 in your phone browser

# to reach it from your laptop on the same wifi:
python3 $HOME/nullscan/tools/serve_local.py --host 0.0.0.0
```

Same engine, same page, zero packages. Verified working with fastapi, pydantic,
starlette and uvicorn hard-blocked at the import hook.

**Dev only.** Single process, in-memory jobs, no metering, no auth. `service/`
stays the real server and the source of truth for the API contract. If you want
to add a feature to the dev server, it belongs in `service/` instead — two
implementations of one API is a drift risk, and the only thing keeping it
manageable is that this one does the bare minimum the page needs.

## 5b. The free public scanner

`uvicorn service.main:app` also serves the landing page at `/`. Drop an APK,
watch it scan, see the declaration render in place.

| Endpoint | Purpose |
|---|---|
| `GET /` | Landing page + scanner |
| `GET /v1/quota` | Free scans remaining for this caller |
| `POST /v1/waitlist` | Build-tracking early access signup |
| `POST /v1/scans?sha256=…` | Re-fetch a cached report with no upload and no quota charge |

Free tier is 3 scans per day, bucketed by /24 (IPv4) or /64 (IPv6) so one
office NAT doesn't get 200 free scans and one phone doesn't lose its quota when
the carrier rotates an octet. An API key bypasses metering entirely — that's
the whole free-vs-paid boundary.

**Set `NULLSCAN_TRUST_PROXY=1` on Railway and nowhere else.** Behind a proxy the
socket peer is the proxy, so every visitor shares one bucket; `X-Forwarded-For`
fixes that. But it's caller-controlled, so honouring it on a directly-exposed
host hands anyone unlimited scans for the price of one header. Pinned by test.

Collected emails:

```bash
sqlite3 /data/jobs.db "SELECT email, datetime(created_at,'unixepoch') FROM waitlist ORDER BY created_at DESC"
```

## 5c. Billing

Two plans, defined in `service/billing.py` — in version control, not in a
dashboard where the two can silently disagree.

| | Price | Scans/month |
|---|---|---|
| Indie | $19 | 200 |
| Studio | $99 | 2,000 |

```bash
export STRIPE_SECRET_KEY=sk_live_...
export STRIPE_WEBHOOK_SECRET=whsec_...
export NULLSCAN_PUBLIC_URL=https://your-domain
```

Point a Stripe webhook at `POST /v1/stripe/webhook` and subscribe to
`checkout.session.completed`, `invoice.paid`, `invoice.payment_failed`,
`customer.subscription.deleted`.

Without those vars, `/v1/checkout` returns 503 and everything else works — so
local dev and self-hosting need no Stripe account.

**Key delivery is automatic.** On `checkout.session.completed` the webhook
issues the key and emails it. Set `RESEND_API_KEY` and it sends; leave it unset
and it logs `PROVISIONED ...` instead, so nothing breaks in test mode.

Mail setup (5 minutes, one-off):

1. resend.com -> sign up -> API Keys -> create one (`re_...`)
2. Railway -> Variables:
   ```
   RESEND_API_KEY=re_...
   NULLSCAN_MAIL_FROM=NULLSCAN <keys@yourdomain.dev>
   ```
3. Resend -> Domains -> add your domain, paste the DNS records at your
   registrar. Takes ~10 min to verify.

**Testing without a domain:** set `NULLSCAN_MAIL_FROM=onboarding@resend.dev`.
Resend allows that sender with no verification, but it will only deliver to the
address you signed up with. Good enough to confirm the pipeline; you need your
own domain before real customers.

Keys live in SQLite with a tier, a status and a Stripe subscription id, so
cancellation is a state change rather than a redeploy. A lapsed key gets
**402 Payment Required**, not a silent downgrade to the free tier — silently
metering someone who is paying is worse than an error they can see.

## 5d. CI gate

`ci/action.yml` is a composite GitHub Action; `.github/workflows/compliance.yml`
is a copy-paste workflow.

```yaml
- uses: ./ci
  with:
    apk: app/build/outputs/apk/release/app-release.apk
    baseline: compliance/baseline.json
```

Exit 1 when the build would make a previously-accurate declaration wrong.
Verified: drift → exit 1, clean → exit 0.

The baseline is the report from the last build you **shipped**, not the last
one you ran. Comparing against the previous commit tells you what changed since
yesterday. Comparing against the shipped build tells you what your live Play
Console listing is now wrong about. Only the second one is worth failing a
build over.

With no `api-key`, the Action runs the local engine and nothing leaves the
runner — which is also the answer for customers whose legal team won't let an
APK off the premises.

## 6. Deploy

`railway.toml` and `Procfile` are ready. Copy `.env.example` to your Railway
environment variables. Mount a volume at `/data`.

One uvicorn worker on purpose: analysis concurrency comes from the
`ProcessPoolExecutor` inside the app (`NULLSCAN_WORKERS`). Multiple uvicorn
workers would each spawn their own pool and each open their own SQLite writer.

---

## Order of work from here

1. **Corpus harvest** → fix whatever `HARVEST.md` flags
2. **Fill in `candidate_signatures.py`** → move into `core/signatures.py`.
   Target ~200 signatures. This table is the moat; it's content, not code.
3. **Free public scanner page** → one APK, no signup, rate-limited by IP
4. **Stripe Checkout** → $19 indie / $99 studio, hosted portal, no custom billing
5. **GitHub Action** wrapping `cli.py diff --fail-on-drift` → this is retention;
   the free scanner is just the funnel

## Where the money is

`core/diff.py`. A scan is a one-time purchase. A diff is a subscription.
"Build 47 added an SDK that reads coarse location and your live declaration
says you don't collect location" is the sentence that gets a card charged
every month. Nobody in this market sells that.
