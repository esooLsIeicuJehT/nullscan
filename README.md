# NULLSCAN

Android compliance scanner. Ingests an APK, emits a Play Data Safety declaration
and a build-over-build compliance drift report.

`48/48` engine tests, `32/32` service tests. No aapt2, no apktool, no subprocess —
the analysis core is pure stdlib Python.

---

## Context Flow map

```
                          ┌─ TRUST BOUNDARY ─┐
  HTTP ── service/main ───┤                  │
  CLI  ── cli.py ─────────┤ core/container   │   validate zip
                          └────────┬─────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             core/axml       core/dex       (lib/*.so listing)
          AndroidManifest   classes*.dex      native surface
                    │              │              │
                    ▼              ▼              │
             ManifestFacts    DexTables           │
                    │         ┌────┴────┐         │
                    │         ▼         ▼         │
                    │  match_sdks   match_sinks   │
                    │  scan_strings               │
                    │         │         │         │
                    └─────────┴────┬────┴─────────┘
                                   ▼
                          core/datasafety
                     ┌─── correlation stage ───┐
                     │ perms + SDKs + sinks    │
                     │   → DeclarationLine[]   │
                     └────────────┬────────────┘
                                  ▼
                             ScanReport
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
              service/store               core/diff
             (SQLite, WAL)            ScanReport × ScanReport
                                              ▼
                                      ComplianceDrift
                                    (the subscription)
```

### Module boundaries

| Layer | May import | Must never import |
|---|---|---|
| `core/` | stdlib only | fastapi, starlette, pydantic, `service` |
| `service/` | `core`, fastapi, pydantic | nothing from `tests` |
| `cli.py` | `core` | `service` |

`tests/test_engine.py [8]` greps for violations and fails the build. That one
test is what keeps this shippable as a hosted API, a CI binary, and an on-prem
wheel from a single source tree.

---

## What changed from the original sketch

| # | Original | Problem | Fix |
|---|---|---|---|
| 1 | `@app.get('/api-scan/')` with `data: dict` | FastAPI reads a bare `dict` param as a **body**. GET bodies aren't sent by requests/httpx/curl/fetch. Route compiles, publishes a broken OpenAPI schema, 422s every real client. | `POST /v1/diff` with a typed `DiffRequest` |
| 2 | `await extract_and_analyze(file)` | `async def` doesn't make CPU-bound work concurrent. A 90 MB multidex walk pins the event loop — health checks included. | `ProcessPoolExecutor` (processes; the GIL makes threads useless here) + 202/poll |
| 3 | `UploadFile` read with no cap | 4 GB upload → OOM kill | streamed to disk, hard ceiling, `Content-Length` never trusted |
| 4 | `-> Dict[str, str]` | Payload is nested and polymorphic. The annotation was a wish; OpenAPI believed it. | Pydantic response models = the published contract |
| 5 | Analysis inside the web app | Can't ship a CLI or on-prem build; can't test the engine without a server | `core/` is framework-free, enforced by test |

Two more found while building, both real DoS vectors:

- **`core/dex.py`** — a corrupt header declaring `type_ids_size = 0xFFFFFFFF` made
  the parser loop 4.3 billion times. Every table is now clamped to what the buffer
  can physically hold. Cheapest possible attack on a scanning service.
- **`core/models.py`** — `asdict()` leaves `str`-Enum members in place. They compare
  equal to their value but **hash by name**, so `"financial" in {DataCategory.FINANCIAL}`
  is `False`. Silently broke every set operation in the diff engine. Normalised at
  the serialization boundary.

---

## Run it

```bash
cd /home/claude/nullscan
pip install -r requirements.txt --break-system-packages

# tests
python3 /home/claude/nullscan/tests/test_engine.py
python3 /home/claude/nullscan/tests/test_service.py

# CLI
python3 /home/claude/nullscan/cli.py scan /path/to/app.apk
python3 /home/claude/nullscan/cli.py scan /path/to/app.apk --json > report.json
python3 /home/claude/nullscan/cli.py diff baseline.json candidate.apk --fail-on-drift

# API
uvicorn service.main:app --reload --port 8000
```

### API flow

```bash
curl -sX POST http://localhost:8000/v1/scans -F file=@app.apk
# → 202 {"job_id":"...","state":"queued","poll_url":"/v1/scans/...","cached":false}

curl -s http://localhost:8000/v1/scans/<job_id>
curl -s http://localhost:8000/v1/scans/<job_id>/declaration

curl -sX POST http://localhost:8000/v1/diff \
  -H 'Content-Type: application/json' \
  -d '{"base_job_id":"...","head_job_id":"..."}'
```

Re-uploading an identical APK is a SHA-256 cache hit and returns `200` with
`cached: true` — CI re-runs cost nothing, which is what makes a free tier viable.

---

## CI gate

```yaml
# .github/workflows/compliance.yml
- run: python3 cli.py diff baseline.json app/build/outputs/apk/release/app-release.apk --fail-on-drift
```

Exit 1 when the build would make a previously-accurate Data Safety form wrong,
or introduces a new high-severity finding. Verified: `CI EXIT CODE = 1`.

---

## Corpus validation (do this before anything else)

```bash
# 1. build a real corpus from your own phone (third-party apps only)
bash /home/claude/nullscan/tools/pull_corpus.sh /home/jigga/apk-corpus 40

# 2. run the engine across all of it
python3 /home/claude/nullscan/tools/harvest.py /home/jigga/apk-corpus \
        --out /home/jigga/apk-corpus-results
```

Produces:

| File | What it's for |
|---|---|
| `HARVEST.md` | Ship gate — PASS/HOLD, crashes, silent misses, slowest APKs |
| `engine_health.csv` | Per-APK row: size, dex count, obfuscation %, SDKs found |
| `candidate_signatures.py` | Paste-ready stubs for every unmatched library, ranked by app frequency |
| `harvest.json` | Machine-readable, for tracking corpus health across engine versions |

Four failure modes it separates, in priority order:

1. **CRASH** — an exception escaped the engine. Fix first.
2. **manifest_failed** — AXML undecodable. Usually a resource-reference or an
   AAPT2 variant the decoder doesn't handle.
3. **zero_sdk_suspicious** — 500+ classes and zero recognised SDKs. The *silent*
   failure: a "successful" scan that ships a wrong declaration. Worse than a crash,
   because nothing alerts you.
4. **rejected** — container refused it. Usually correct behaviour.

The `obfuscation_pct` column predicts where string-based rules degrade. If your
corpus is 60%+ obfuscated and detection holds up, the approach is sound.

---

## Deliberate scope limits

**No bytecode reachability.** We parse DEX *reference tables*, not method bodies.
A reference to `TelephonyManager;->getDeviceId` proves the API is linked; proving
it's *reachable* costs ~40× the CPU and changes the answer for a small minority of
apps. When the "that's dead code in a library" complaint arrives — and it will —
that becomes an opt-in second pass behind the same interface. The boundary is
already drawn in `core/dex.py`.

**No native analysis.** `.so` files are enumerated and flagged, not disassembled.
Your GhostDroidCompanion ELF inspector is the natural next module and slots in as
a fourth evidence stream into `core/datasafety.build_declaration`.

**No resources.arsc parsing.** String resources referenced as `@0x7f...` in the
manifest stay unresolved. Rarely matters for compliance; add an `arsc.py` producing
an id→string map and pass it to `_format_value` when it does.

---

## Where the money is

`core/diff.py`. A scan is a one-time purchase. A diff is a subscription. The
sentence *"build 47 added an SDK that reads coarse location and your live
declaration says you don't collect location"* is what gets a card charged monthly.
Nobody in this market sells that.

## Next module

`core/arsc.py` for resource resolution, then widen `SDK_SIGNATURES` from 36 to
~200 — that table is the moat, and it's content, not code. Seed it by scanning
the top 500 free apps and clustering unmatched class prefixes by frequency.
