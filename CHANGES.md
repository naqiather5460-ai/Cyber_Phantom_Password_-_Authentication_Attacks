# AuthGuard AI v1.0 → v1.1: what was fixed

## Critical security
| # | Problem in v1.0 | Fix |
|---|---|---|
| 1 | **MFA accepted any 6-digit code** (comment: "or 123456") | Real RFC 6238 TOTP, base32 secrets, ±1 window, replay-protected, 5 attempts per challenge, single-use token |
| 2 | **Hard-coded production secrets** in `config.py` and `docker-compose.yml` | Env-only; random ephemeral secrets in dev; service refuses to start in production without real ones |
| 3 | **Telemetry/audit/user-profile endpoints were unauthenticated** (`x_api_key` declared, never checked) | All `/telemetry/*` require `X-API-Key` (constant-time compare) |
| 4 | **Spoofable client telemetry**: browser-sent ASN/country/device decided "familiar" | Ignored unless trusted (dev, or gateway API key); UA parsed server-side; fail-closed step-up without trusted location |
| 5 | **Forgeable client IP**: `X-Forwarded-For` / `CF-Connecting-IP` trusted from anyone (bypassed rate limit + IP block) | Opt-in `AUTHGUARD_TRUST_PROXY_HEADERS`; right-most XFF entry |
| 6 | **IP penalty box never triggered**: the "check" call recorded a *success*, resetting failures to 0 each request | Read-only `is_ip_blocked`, real failure counting, decay, exponential block, success only decrements |
| 7 | **PoW was theatre**: salts not stored, not IP-bound/expiring/single-use, and solving did nothing → valid users in the tarpit band could never log in | Persisted, IP-bound, expiring, single-use; solved PoW downgrades tarpit to step-up |
| 8 | **Account confusion**: `user_id` could equal another user's email; lookup `user_id = ? OR email = ?` was ambiguous | `user_id` pattern forbids `@`; exact-ID-then-email lookup; emails normalised |
| 9 | **CORS `*` with credentials** | Explicit allow-list; wildcard rejected in production |
| 10 | Honeyword hashes were bare SHA-256, held only in process memory (lost on restart, per-worker) | Keyed PBKDF2 sweetwords persisted in SQLite; hydrated per request; constant-time scan |
| 11 | Honeyword decoys were 1-edit typos of the real password → false canary alarms on real users | Decoys ≥ 3 edits away |
| 12 | `time.sleep()` tarpit inside sync handlers blocked threadpool threads (self-DoS) | `async` login, work in threadpool, `asyncio.sleep` |
| 13 | Refresh tokens had no endpoint / rotation; MFA token replayable | `/auth/refresh` with rotation; token ledger |
| 14 | Exception text leaked in token errors; unvalidated `X-Request-ID` echoed | Generic errors; ID validated |

## Correctness / reliability
* **RBA device mismatch**: dataset stores `desktop`, runtime sent `Desktop` → device familiarity never matched. Normalised.
* **Cold start**: new users stayed "unfamiliar" forever (baselines never updated). Verified logins now update a persisted baseline; first login on a new device requires TOTP.
* **Zero-trust floor** in the agent: ML score alone allowed a fully unfamiliar context (risk ≈ 0.23 < 0.25).
* Two `AuthGuardAgent` instances (one per router) with divergent state → one shared singleton.
* SQLite connections were never closed (`with conn` only commits) → context manager that closes.
* Swagger UI was blank behind the strict CSP; health endpoint reported a static "sqlite_wal_active"; `datetime.utcnow()` deprecated.
* `risk_breakdown` always reported familiarity 0 (read a key that never existed) → real values.
* `rtt_ms: null` crashed the evaluate endpoint (500).
* Login-specific rate limit setting existed but was never applied.

## Packaging & docs
* `requirements.txt`: added missing `email-validator` (import crash), **pinned scikit-learn==1.9.1** to match the pickled models, dropped unused packages (lightgbm, shap, seaborn, matplotlib, requests).
* Docker: non-root, read-only rootfs, no 92 MB training CSV or baked-in demo DB in the image, `.dockerignore`, `.env.example`, working healthcheck without `curl`.
* README: corrected metrics to the shipped models (RBA 0.9321 / 0.7648, not 0.9459 / 0.8433), removed a local `file:///d:/...` link and non-existent `dashboard/app.py` / missing CICIDS file references, added honest caveats.
* Demo user `sarah_connor` is now opt-in (`AUTHGUARD_SEED_DEMO_USER`) and refused in production.
* Tests: 13 → 27, now over real HTTP (TestClient) with an isolated DB and regression tests for each bug above.

## Review hardening (2026-10-22)

- JWT verification now validates the token header (`HS256` / `JWT`), requires a numeric expiration claim, and rejects tokens at the exact expiration boundary.
- Password-hash verification rejects malformed salts/digests and iteration counts outside the supported 100,000–2,000,000 range, preventing corrupted stored records from causing unbounded CPU work on login.
- `/health` now returns HTTP 503 when the database or either required ML model is unavailable, so container/orchestrator readiness checks detect degraded service instead of treating it as healthy.
- Added regression tests for strict JWT expiry and malformed/unbounded password-hash records.
- Validation: `pytest -q` — 29 passed. The current analysis environment has scikit-learn 1.8.0 while the shipped models and `requirements.txt` specify 1.9.1, so model-load compatibility warnings appear here; use the pinned requirements (or Docker build) for a version-matched runtime.
