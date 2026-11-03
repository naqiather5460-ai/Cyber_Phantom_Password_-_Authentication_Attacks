# AuthGuard AI: Zero-Trust Authentication Threat Diagnosis & Adaptive Prevention

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-green.svg)](https://fastapi.tiangolo.com)

A low-latency autonomous security agent that detects, diagnoses and adaptively mitigates password and
authentication attacks (credential stuffing, brute force, AI-assisted guessing, account takeover).
Inspired by Risk-Based Authentication (Freeman et al.; Wiefling et al.) and motivated by the 23andMe
credential-stuffing incident.

## Team and Work Done

AuthGuard AI (v1.1) was built by a team of three, each owning one layer of the system. Task 6, Part A, AI Engineering Internship.

### Naqi: Backend and Security
- Built the core service in `src/core/`: config, SQLite database, middleware, PBKDF2 password hashing (200,000 iterations), JWT access tokens with single-use refresh rotation, TOTP step-up (RFC 6238) and proof-of-work puzzles.
- Wrote the auth and telemetry API routes in `src/api/`, including per-IP rate limiting and the API-key-protected `/telemetry/*` endpoints.
- Packaged the service with Docker, docker-compose and `.env.example`. In production mode the service refuses to start without a secret key and API key.
- Wrote the end-to-end backend tests (`test_backend_e2e.py`).

### Mayam: ML Risk Models
- Trained the **Network Threat Engine** on CICIDS-2017 Tuesday traffic (FTP-Patator and SSH-Patator brute force vs benign).
- Trained the **Behavioural RBA Engine** on the Das-Group RBA curated sample. It scores how familiar a login's IP, ASN, country, device and browser are against the user's own history, using HistGradientBoosting with Platt calibration.
- Wrote the data preparation (`src/utils/prepare_datasets.py`) and the retraining script (`train_all.py`).
- Evaluated both models on a held-out 20 % split:

| Model | ROC-AUC | PR-AUC |
| --- | --- | --- |
| Network Threat Engine | 0.99999866 | 0.99998 |
| Behavioural RBA Engine | 0.9321 | 0.7648 |

### Umair: Decision Agent and Deception
- Wrote the decision agent (`src/agent/authguard_agent.py`). It fuses both model scores, applies a zero-trust floor (no frictionless ALLOW without a known location and at least two known device signals) and picks one of five actions: ALLOW, STEP_UP, TARPIT, BLOCK or DECEPTIVE_QUARANTINE.
- Built the honeyword engine (`deceptive_engine.py`): keyed decoy passwords at least 3 edits from the real one, so ordinary typos do not set off the alarm. A decoy hit sends the attacker to a decoy session and raises an alert.
- Wrote the attack scenarios and demo tooling (`try_login.py`, `seed_dummy_data.py`) and the agent tests (`test_agent.py`).

### Shared work
- Research, literature review, problem statement and the project proposal, with each member writing the sections for their own layer.
- 27 automated tests, all passing in about 10 seconds.
- A review of our own results and the limits we found.

### Known limits
- The RBA ROC-AUC target of 0.985 was not met (0.9321).
- The Network Threat Engine score is probably inflated. Its features include Destination Port, and the brute-force traffic targets ports 21 and 22. We have not yet tested it on other days of CICIDS-2017.
- The RBA split is random rather than chronological, so the result is likely optimistic.
- There is no per-account throttle yet, so a slow, distributed password spray is not stopped.
- SQLite and the in-process rate limiter suit a single node only.

## Architecture

```
 Login request ──► IP penalty box ──► PBKDF2 verify (dummy hash for unknown users)
                                              │ wrong password?
                                              ▼
                               Honeyword canary (keyed PBKDF2 sweetwords)
                                              │
        ┌─────────────────────────────────────┴───────────────┐
        ▼                                                     ▼
 Network Threat Engine (gateway-supplied flow)      Behavioral RBA Engine (per-user baseline)
        └──────────────► risk fusion + zero-trust floor ◄─────┘
                                   │
   ALLOW ── STEP_UP (TOTP) ── TARPIT (+proof-of-work) ── BLOCK ── DECEPTIVE_QUARANTINE
```

## Quick start

```bash
pip install -r requirements-dev.txt
python -m unittest discover -s tests -t .          # 27 tests, ~10 s
AUTHGUARD_SEED_DEMO_USER=true uvicorn src.api.main:app --reload   # dev server, docs at /docs
```

Production (Docker):

```bash
cp .env.example .env     # fill AUTHGUARD_SECRET_KEY and AUTHGUARD_API_KEY (the service refuses to start without them)
docker compose up --build -d
```

## Configuration (environment variables)

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `AUTHGUARD_ENV` | `development` | `production` enforces secrets, disables `/docs`, forbids demo seeding and wildcard CORS |
| `AUTHGUARD_SECRET_KEY` | random per process (dev) | JWT signing + honeyword pepper. **Required in production**, ≥ 32 chars |
| `AUTHGUARD_API_KEY` | random per process (dev) | `X-API-Key` for `/telemetry/*` and gateway-injected telemetry. **Required in production** |
| `AUTHGUARD_CORS_ORIGINS` | localhost dev origins | Comma-separated allow-list |
| `AUTHGUARD_TRUST_PROXY_HEADERS` | `false` | Honour `CF-Connecting-IP` / `X-Forwarded-For` (only behind a proxy you control) |
| `AUTHGUARD_TRUST_CLIENT_TELEMETRY` | `true` in dev, `false` in prod | Accept browser-reported ASN/country/city/RTT |
| `AUTHGUARD_DB_PATH` | `var/authguard.db` | SQLite file (mount `/app/var` as a volume) |
| `RATE_LIMIT_LOGIN` / `RATE_LIMIT_GLOBAL` | `25` / `150` | Requests per minute per IP (per worker process) |

### Important deployment note: location data
The behavioral engine needs a *trustworthy* network location. Browser-supplied ASN/country can be forged by
an attacker holding stolen credentials, so in production they are ignored unless the request carries your
service API key. Inject them from your CDN/gateway (e.g. `CF-IPCountry` is read automatically when proxy
headers are trusted, or have your BFF forward `asn`/`country`/`city` with `X-API-Key`). Without any trusted
location the engine fails *closed*: every login is a step-up challenge.

## Repository structure

```
├── src/
│   ├── agent/        authguard_agent.py (decision matrix), deceptive_engine.py (honeywords)
│   ├── api/          main.py, schemas.py, routes/{auth,telemetry}.py
│   ├── core/         config, database (SQLite), middleware, security (PBKDF2/JWT/TOTP/PoW), telemetry (UA parsing)
│   ├── models/       network_threat_engine.py, behavioral_rba_engine.py
│   └── utils/        prepare_datasets.py
├── models/           trained, calibrated models (.joblib) - scikit-learn 1.9.1
├── data/             rba_docs/ (docs and images from the RBA dataset authors)
├── tests/            test_agent.py, test_backend_e2e.py
├── train_all.py      retrains both engines
├── Dockerfile, docker-compose.yml, .env.example
└── FULLSTACK_INTEGRATION_GUIDE.md, RESEARCH_AND_PROJECT_PROPOSAL.md
```

`data/Tuesday-WorkingHours.pcap_ISCX.csv` (CICIDS-2017) is **not** included; download it to retrain the
Network Threat Engine (`python train_all.py`). The SOC dashboard referenced by earlier versions was never
part of this repository; the SOC endpoints under `/api/v1/telemetry/*` provide the data for one.

## Measured results (from the shipped model artifacts)

| Component | Dataset | ROC-AUC | PR-AUC | Notes |
| :--- | :--- | :--- | :--- | :--- |
| Network Threat Engine | CICIDS-2017 Tuesday (held-out 20 %) | 0.99999866 | 0.99998 | See caveat below |
| Behavioral RBA Engine | Das-Group RBA curated sample (held-out 20 %) | **0.9321** | **0.7648** | Platt-calibrated HistGradientBoosting |

Earlier versions of this README quoted RBA ROC-AUC 0.9459 / PR-AUC 0.8433 and NTE "1.0000"; those do not match
the saved models and were corrected. The proposal's target of ROC-AUC > 0.985 on RBA is **not** met by the
current model.

**Caveats (read before citing the numbers)**
* The NTE feature set includes `Destination Port`. FTP/SSH-Patator traffic targets ports 21/22, so a near-perfect
  score probably reflects port and flow-shape separability on a single day of lab traffic rather than
  generalisation. Run an ablation without port and evaluate on another CICIDS day before claiming more.
* The RBA baseline is built from a random (not chronological) split, so a test row's user profile can include
  that user's *later* logins. Use a time-based split for a stricter estimate.
* Familiarity alone does not separate attacks well (a fully-unfamiliar context scores ≈ 0.23), which is why the
  agent adds a zero-trust floor: no frictionless ALLOW without a known location and ≥ 2 known device signals.

## Security model (v1.1)

* PBKDF2-HMAC-SHA256 (200k) passwords; dummy-hash work for unknown users; constant-time comparisons.
* Real RFC 6238 TOTP step-up (replay-protected, 5 attempts per challenge, single-use challenge token).
* Honeyword sweetwords are keyed PBKDF2 (server pepper), persisted in SQLite, decoys ≥ 3 edits from the real
  password so everyday typos do not raise false canary alarms.
* Server-issued, IP-bound, single-use, expiring proof-of-work; a solved puzzle downgrades the tarpit to step-up.
* Durable per-IP penalty box with exponential back-off; tarpit uses `asyncio.sleep` (no blocked worker threads).
* All `/telemetry/*` endpoints require `X-API-Key`. Refresh tokens rotate (single use).

## Known limitations

* SQLite + per-process rate limiter: fine for a single node; use PostgreSQL/Redis for multi-node.
* No per-account lockout/throttle yet (the IP penalty box does not stop a distributed low-and-slow spray).
* The Network Threat Engine consumes flow features that only a gateway/IDS can supply; browsers cannot.
* `/auth/register` has no email verification; `access_token`s are stateless (no server-side revocation list).
* `RESEARCH_AND_PROJECT_PROPOSAL.md` and the executive report (`.docx`/`.pdf`) describe v1.0 and quote its
  13 tests / MFA behaviour; regenerate them from this version before circulating.
