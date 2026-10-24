# AuthGuard AI - Fullstack Integration Guide (v1.1)

- **Base URL:** `http://localhost:8000/api/v1` · **Swagger:** `/docs` (development only) · **Health:** `GET /health`
- **Two audiences:** browsers call `/auth/*`. Your **server/gateway** calls `/telemetry/*` with `X-API-Key` (never ship that key to a browser).

## Decision matrix for `POST /auth/login`

| HTTP | `decision` | Frontend action |
| :-- | :-- | :-- |
| 200 | `ALLOW` | Keep `access_token` **in memory**, `refresh_token` in an httpOnly cookie (set by your BFF) - not `localStorage`. |
| 401 | `STEP_UP_CHALLENGE` | Show a TOTP prompt; `POST /auth/mfa/verify` with `mfa_token` + 6-digit code. |
| 429 | `TARPIT_THROTTLE` | Solve `pow_challenge`, `POST /auth/pow/verify`, then retry login **once**. |
| 401 | `DENIED` | Generic "Invalid username or password." |
| 403 | `BLOCK_AND_QUARANTINE` / IP blocked | Show a generic block message; honour `Retry-After`. |
| 200 | `DECEPTIVE_QUARANTINE` | Server-side canary only (the token is fake). Treat like `ALLOW` in the UI - never special-case it client-side. |

A first login from a new device is always a step-up. After a successful TOTP step the device/network becomes
trusted and later logins from it are frictionless.

## Registration - `POST /auth/register`

Body: `{ "email", "password" (8-128), "user_id"? (3-64 chars: letters, digits, _ . -) }`.
Response includes `mfa_secret` (base32) and `mfa_provisioning_uri` (`otpauth://`): render as a QR code **once**
so the user can enrol an authenticator app. The secret is not retrievable later.

## Login handler (TypeScript)

```typescript
let accessToken: string | null = null;           // memory only

async function handleLogin(username: string, password: string, retried = false) {
  const res = await fetch("/api/v1/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    // Do NOT send asn/country/city/rtt from the browser: they are ignored in production
    // (they would be trivially forgeable). Location is derived server-side / by your gateway.
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();

  if (res.status === 200 && data.decision === "ALLOW") { accessToken = data.access_token; return data; }
  if (res.status === 401 && data.decision === "STEP_UP_CHALLENGE") return promptMfa(data.mfa_token);
  if (res.status === 429 && data.decision === "TARPIT_THROTTLE" && !retried) {
    const nonce = await solveProofOfWork(data.pow_challenge.challenge_salt, data.pow_challenge.difficulty);
    await fetch("/api/v1/auth/pow/verify", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge_salt: data.pow_challenge.challenge_salt, nonce: String(nonce) }),
    });
    return handleLogin(username, password, true);       // retry exactly once - no infinite loop
  }
  throw new Error(data.detail ?? "Sign-in failed");
}
```

## Step-up - `POST /auth/mfa/verify`

```typescript
async function submitMfaCode(mfaToken: string, code: string) {
  const res = await fetch("/api/v1/auth/mfa/verify", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mfa_token: mfaToken, mfa_code: code }),   // code: exactly 6 digits
  });
  if (res.status === 429) throw new Error("Too many attempts - sign in again.");   // 5 tries per challenge
  if (!res.ok) throw new Error("Invalid verification code");
  return res.json();                                                // access_token + refresh_token
}
```
The challenge token is valid 5 minutes, single use, and a TOTP code can be used only once.

## Token refresh - `POST /auth/refresh`
`{ "refresh_token": "..." }` → new access + refresh pair. **Refresh tokens rotate**: reusing one returns 401.

## Proof-of-work solver

Hash input is `"<challenge_salt>:<nonce>"` (SHA-256, hex must start with `difficulty` zeros). Challenges are
server-issued, tied to your IP, expire in 180 s and work once.

```typescript
async function solveProofOfWork(salt: string, difficulty: number): Promise<number> {
  const prefix = "0".repeat(difficulty), enc = new TextEncoder();
  for (let nonce = 0; ; nonce++) {
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(`${salt}:${nonce}`));
    const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    if (hex.startsWith(prefix)) return nonce;
  }
}
```

## Current user - `GET /auth/me` (`Authorization: Bearer <access_token>`)

## Back-office / gateway endpoints (require `X-API-Key`)

| Endpoint | Purpose |
| :-- | :-- |
| `POST /telemetry/evaluate` | Risk score for a session (for Envoy/Kong/AWS API Gateway) |
| `GET /telemetry/soc-overview` | Aggregate metrics for dashboards |
| `GET /telemetry/audit-logs?limit=50` | Recent audit trail |
| `GET /telemetry/user-risk-profile/{user_id}` | Baseline familiarity profile |

Gateway-injected login telemetry: forward the browser's login request with `X-API-Key` and add
`asn`, `country`, `city`, `rtt_ms` (and optionally `network_flow`) to the JSON body.

## Security properties
1. Passwords: PBKDF2-HMAC-SHA256, 200,000 rounds, unique 16-byte salts; dummy-hash work for unknown users.
2. TOTP (RFC 6238): replay-protected, attempt-limited, challenge single-use.
3. Secure headers on every response; strict CSP on the API (relaxed only for `/docs` in development).
4. CORS is an explicit allow-list (`AUTHGUARD_CORS_ORIGINS`); wildcard is rejected in production.
5. Audit logs store IP/ASN/geo/UA (personal data under GDPR-style regimes - set a retention policy); passwords are never logged.
6. Sanitised RFC 7807-style errors; `X-Request-ID` values are validated before being echoed.
