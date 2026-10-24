"""
AuthGuard AI - Authentication router.
Registration, risk-adaptive login, TOTP step-up, proof-of-work tarpit, token refresh.

Key properties
* No blocking sleeps: tarpit delays use asyncio.sleep, CPU/DB work runs in the threadpool.
* Client-reported geo/ASN/RTT is ignored unless explicitly trusted (see config) - an attacker holding
  stolen credentials must not be able to *claim* the victim's usual network to dodge step-up.
* MFA tokens are attempt-limited and single-use; TOTP codes cannot be replayed.
* Proof-of-work challenges are server-issued, IP-bound, expiring and single-use, and a solved puzzle
  actually changes the next login decision.
"""

import asyncio
import re
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.agent.authguard_agent import get_agent
from src.api.schemas import (
    LoginRequest, LoginSuccessResponse, MFAVerifyRequest, POWVerifyRequest,
    RefreshRequest, UserRegisterRequest, UserRegisterResponse,
)
from src.core.config import settings
from src.core.database import db
from src.core.security import security
from src.core.telemetry import parse_user_agent

router = APIRouter(prefix="/auth", tags=["Authentication & Identity"])
agent = get_agent()
auth_scheme = HTTPBearer(auto_error=False)

DEMO_MFA_SECRET = "JBSWY3DPEHPK3PXP"  # development demo account only
if settings.SEED_DEMO_USER and not db.get_user("sarah_connor"):
    db.create_user("sarah_connor", "sarah@cyberdyne.org",
                   security.hash_password("SkynetKiller2024!"), DEMO_MFA_SECRET)
    agent.deception_engine.register_user_credentials("sarah_connor", "SkynetKiller2024!")
    _rec = agent.deception_engine.honeychecker_store["sarah_connor"]
    db.store_honeywords("sarah_connor", _rec["true_index"], _rec["word_hashes"])

# Same PBKDF2 work for unknown usernames -> no user enumeration by response time.
DUMMY_HASH = security.hash_password("dummy_password_for_timing_mitigation_123")


# --------------------------------------------------------------------------- helpers
@dataclass
class Outcome:
    response: JSONResponse
    delay: float = 0.0


def _headers(request: Request) -> Dict[str, str]:
    return {k.lower(): v for k, v in request.headers.items()}


def _client_ip(request: Request, headers: Dict[str, str]) -> str:
    return security.extract_client_ip(headers, request.client.host if request.client else "127.0.0.1")


def _resolve_context(req: LoginRequest, headers: Dict[str, str], is_gateway: bool) -> Dict[str, Any]:
    """Builds the session context from the most trustworthy source available."""
    ua = parse_user_agent(headers.get("user-agent", ""))
    trust_body = settings.TRUST_CLIENT_TELEMETRY or is_gateway
    geo_country = headers.get("cf-ipcountry") if settings.TRUST_PROXY_HEADERS else None

    def pick(body_value, fallback):
        return body_value if (trust_body and body_value) else fallback

    return {
        "asn": pick(req.asn, "UNKNOWN"),
        "country": pick(req.country, geo_country or "XX"),
        "city": pick(req.city, "Unknown"),
        "device_type": pick(req.device_type, ua["device_type"]),
        "browser": pick(req.browser, ua["browser"]),
        "os": pick(req.os, ua["os"]),
        "rtt_ms": float(req.rtt_ms) if (trust_body and req.rtt_ms) else 50.0,
    }


def _issue_tokens(user_id: str, mfa_verified: bool = False) -> Dict[str, Any]:
    claims = {"sub": user_id, "type": "access", "role": "user"}
    if mfa_verified:
        claims["mfa_verified"] = True
    access = security.create_jwt_token(claims, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    refresh = security.create_jwt_token({"sub": user_id, "type": "refresh"},
                                        settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "expires_in_seconds": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60}


def _new_pow(ip: str) -> Dict[str, Any]:
    challenge = security.generate_pow_challenge(ip, difficulty=settings.POW_DIFFICULTY)
    db.store_pow_challenge(challenge["challenge_salt"], ip, challenge["difficulty"])
    return challenge


def _audit(request_id: str, user_id: str, ip: str, ctx: Dict[str, Any], decision: str,
           risk: float, threat: str, latency_ms: float) -> None:
    db.log_event({"request_id": request_id, "user_id": user_id, "ip_address": ip, "asn": ctx.get("asn"),
                  "country": ctx.get("country"), "city": ctx.get("city"), "browser": ctx.get("browser"),
                  "os": ctx.get("os"), "decision": decision, "risk_score": risk,
                  "threat_type": threat, "latency_ms": latency_ms})


# ---------------------------------------------------------------------- registration
@router.post("/register", response_model=UserRegisterResponse, status_code=status.HTTP_201_CREATED)
def register(req: UserRegisterRequest):
    """Creates an account: PBKDF2 hash, base32 TOTP secret, and keyed honeyword decoys."""
    local = re.sub(r"[^A-Za-z0-9_.-]", "_", req.email.split("@")[0])
    user_id = req.user_id or (local if len(local) >= 3 else f"user_{local}")[:64]

    if db.user_or_email_exists(user_id, req.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this ID or email already exists.")

    mfa_secret = security.generate_totp_secret()
    if not db.create_user(user_id, req.email, security.hash_password(req.password), mfa_secret):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this ID or email already exists.")

    agent.deception_engine.register_user_credentials(user_id, req.password)
    record = agent.deception_engine.honeychecker_store[user_id]
    db.store_honeywords(user_id, record["true_index"], record["word_hashes"])

    return UserRegisterResponse(
        user_id=user_id, email=req.email, status="active", honeywords_armed=settings.HONEYWORDS_COUNT,
        mfa_secret=mfa_secret, mfa_provisioning_uri=security.totp_uri(mfa_secret, req.email),
        created_at=time.time())


# ---------------------------------------------------------------------------- login
def _login_core(req: LoginRequest, request: Request) -> Outcome:
    start = time.perf_counter()
    headers = _headers(request)
    ip = _client_ip(request, headers)
    request_id = getattr(request.state, "request_id", "req_unknown")
    is_gateway = security.is_service_key(headers.get("x-api-key"))

    # 1. Penalty box (read-only check)
    block = db.is_ip_blocked(ip)
    if block["is_blocked"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "This IP address is temporarily blocked due to repeated failed authentication.",
                            headers={"Retry-After": str(block["retry_after"])})

    # 2. User lookup (dummy hash for unknown users keeps timing uniform)
    user = db.get_user(req.username)
    user_id = user["user_id"] if user else req.username
    credentials_matched = security.verify_password(req.password, user["password_hash"] if user else DUMMY_HASH) \
        and user is not None

    ctx = _resolve_context(req, headers, is_gateway)

    # 3. Honeyword canary - only evaluated when the real password did not match
    if not credentials_matched:
        if user:
            agent.deception_engine.hydrate(user_id, db.get_honeywords(user_id))
            honey = agent.deception_engine.verify_attempt(user_id, req.password)
        else:
            agent.deception_engine.dummy_work()
            honey = {}
        if honey.get("is_honeyword"):
            latency = (time.perf_counter() - start) * 1000
            db.record_ip_failure(ip)
            _audit(request_id, user_id, ip, ctx, "DECEPTIVE_QUARANTINE", 0.999,
                   "HONEYWORD_DATABASE_LEAK_EXPLOITATION", latency)
            return Outcome(JSONResponse(status_code=200, content={
                "decision": "DECEPTIVE_QUARANTINE",
                "access_token": f"canary_quarantine_{secrets.token_hex(24)}",
                "token_type": "bearer", "expires_in_seconds": 60, "user_id": user_id,
                "risk_score": 0.999, "threat_type": "HONEYWORD_DATABASE_LEAK_EXPLOITATION",
                "detail": "Deception canary triggered. Synthetic honeyword submitted from breached database.",
                "latency_ms": round(latency, 2)}), delay=1.0)

    # 4. Behavioral baseline (persisted, shared across workers)
    if user:
        baseline = db.get_baseline(user_id)
        if baseline:
            agent.rba_engine.user_profiles[user_id] = baseline

    session_ctx = dict(ctx, user_id=user_id, hour=time.localtime().tm_hour,
                       login_successful=1 if credentials_matched else 0,
                       is_weekend=1 if time.localtime().tm_wday in (5, 6) else 0)
    network_flow = req.network_flow if is_gateway else None   # a browser has no business supplying this

    evaluation = agent.evaluate_login_request(
        user_id=user_id, password_candidate=req.password, session_context=session_ctx,
        network_flow=network_flow, check_honeywords=False)
    decision, risk, threat = evaluation["decision"], evaluation["risk_score"], evaluation["threat_type"]

    # 5. A solved proof-of-work relaxes the tarpit (it proves cost, not identity)
    if decision == "TARPIT_THROTTLE" and db.is_pow_cleared(ip):
        decision = "STEP_UP_CHALLENGE" if credentials_matched else "DENIED"

    latency = (time.perf_counter() - start) * 1000
    _audit(request_id, user_id, ip, ctx, decision, risk, threat, latency)
    breakdown = evaluation.get("risk_breakdown", {})

    if not credentials_matched:
        db.record_ip_failure(ip)
        if decision == "TARPIT_THROTTLE":
            return Outcome(JSONResponse(status_code=429, content={
                "decision": "TARPIT_THROTTLE", "pow_challenge": _new_pow(ip),
                "delay_seconds": settings.TARPIT_DELAY_SECONDS, "risk_score": risk, "threat_type": threat,
                "detail": "Invalid credentials with suspicious attack patterns. Rate throttled. Complete Proof-of-Work puzzle.",
                "latency_ms": round(latency, 2), "risk_breakdown": breakdown}),
                delay=settings.TARPIT_DELAY_SECONDS)
        return Outcome(JSONResponse(status_code=401, content={
            "decision": "DENIED", "risk_score": risk,
            "threat_type": threat if threat != "BENIGN_NORMAL_USER" else "INVALID_CREDENTIALS",
            "detail": "Invalid username or password.", "latency_ms": round(latency, 2),
            "risk_breakdown": breakdown}))

    db.record_ip_success(ip)

    if decision == "ALLOW":
        agent.rba_engine.learn_session(user_id, ctx)            # keep the baseline fresh
        db.save_baseline(user_id, agent.rba_engine.user_profiles[user_id])
        return Outcome(JSONResponse(status_code=200, content={
            "decision": "ALLOW", **_issue_tokens(user_id), "user_id": user_id, "risk_score": risk,
            "threat_type": threat, "latency_ms": round(latency, 2)}))

    if decision == "STEP_UP_CHALLENGE":
        mfa_token = security.create_jwt_token(
            {"sub": user_id, "type": "mfa_challenge", "risk": risk,
             "ctx": {k: str(v)[:64] for k, v in ctx.items()}},   # signed: becomes the baseline on success
            settings.MFA_TOKEN_EXPIRE_MINUTES * 60)
        return Outcome(JSONResponse(status_code=401, content={
            "decision": "STEP_UP_CHALLENGE", "mfa_token": mfa_token,
            "supported_methods": ["totp_authenticator"], "risk_score": risk, "threat_type": threat,
            "detail": "Unfamiliar device, network or location. Secondary verification required.",
            "latency_ms": round(latency, 2)}))

    if decision == "TARPIT_THROTTLE":
        return Outcome(JSONResponse(status_code=429, content={
            "decision": "TARPIT_THROTTLE", "pow_challenge": _new_pow(ip),
            "delay_seconds": settings.TARPIT_DELAY_SECONDS, "risk_score": risk, "threat_type": threat,
            "detail": "Suspicious automated activity detected. Complete the Proof-of-Work puzzle to proceed.",
            "latency_ms": round(latency, 2)}), delay=settings.TARPIT_DELAY_SECONDS)

    return Outcome(JSONResponse(status_code=403, content={
        "decision": "BLOCK_AND_QUARANTINE", "risk_score": risk, "threat_type": threat,
        "detail": "Access blocked due to high-risk anomaly.", "latency_ms": round(latency, 2),
        "risk_breakdown": breakdown}))


@router.post("/login")
async def login(req: LoginRequest, request: Request):
    """Risk-adaptive login. Heavy work runs in the threadpool; tarpit delays never block a worker thread."""
    outcome = await run_in_threadpool(_login_core, req, request)
    if outcome.delay:
        await asyncio.sleep(outcome.delay)
    return outcome.response


# ------------------------------------------------------------------------ MFA / PoW
@router.post("/mfa/verify", response_model=LoginSuccessResponse)
def verify_mfa(req: MFAVerifyRequest, request: Request):
    """Verifies the step-up token and a real RFC 6238 TOTP code (replay-protected, attempt-limited)."""
    start = time.perf_counter()
    headers = _headers(request)
    ip = _client_ip(request, headers)

    block = db.is_ip_blocked(ip)
    if block["is_blocked"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Too many failed attempts.",
                            headers={"Retry-After": str(block["retry_after"])})

    valid, claims, _ = security.decode_and_verify_token(req.mfa_token)
    if not valid or claims.get("type") != "mfa_challenge" or not claims.get("jti"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired MFA challenge token.")

    attempt = db.register_attempt(claims["jti"], claims["exp"], settings.MFA_MAX_ATTEMPTS)
    if attempt == "spent":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired MFA challenge token.")
    if attempt == "limit":
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            "Too many attempts for this challenge. Please sign in again.")

    user_id = claims["sub"]
    user = db.get_user(user_id)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid verification code.")

    step = security.verify_totp(user.get("mfa_secret") or "", req.mfa_code)
    if step is None:
        db.record_ip_failure(ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid verification code.")
    if not db.advance_mfa_step(user_id, step):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This code was already used. Wait for the next one.")
    if not db.consume_token(claims["jti"], claims["exp"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired MFA challenge token.")

    # Password + MFA both verified: the device/network context becomes trusted baseline
    ctx = claims.get("ctx") or {}
    if ctx:
        agent.rba_engine.learn_session(user_id, ctx)
        db.save_baseline(user_id, agent.rba_engine.user_profiles[user_id])

    risk = float(claims.get("risk", 0.0))
    latency = (time.perf_counter() - start) * 1000
    _audit(getattr(request.state, "request_id", "req_mfa"), user_id, ip, ctx, "ALLOW", risk,
           "MFA_VERIFIED_STEP_UP", latency)
    tokens = _issue_tokens(user_id, mfa_verified=True)
    return LoginSuccessResponse(decision="ALLOW", user_id=user_id, risk_score=risk,
                                threat_type="MFA_VERIFIED_STEP_UP", latency_ms=round(latency, 2), **tokens)


@router.post("/pow/verify")
def verify_pow(req: POWVerifyRequest, request: Request):
    """Verifies a server-issued, IP-bound, single-use proof-of-work solution and clears the tarpit for this IP."""
    ip = _client_ip(request, _headers(request))
    if not security.verify_pow_solution(req.challenge_salt, req.nonce, difficulty=settings.POW_DIFFICULTY):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid Proof-of-Work solution.")
    difficulty = db.consume_pow_challenge(req.challenge_salt, ip)
    if difficulty is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown, expired, or already-used challenge.")
    if not security.verify_pow_solution(req.challenge_salt, req.nonce, difficulty=difficulty):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid Proof-of-Work solution.")
    db.mark_pow_cleared(ip)
    return {"status": "verified", "detail": "Proof-of-work accepted. Retry your sign-in.",
            "difficulty_solved": difficulty, "clearance_seconds": settings.POW_CLEARANCE_SECONDS}


# ------------------------------------------------------------------- tokens / identity
@router.post("/refresh")
def refresh(req: RefreshRequest):
    """Rotates a refresh token: each refresh token works exactly once."""
    valid, claims, _ = security.decode_and_verify_token(req.refresh_token)
    if not valid or claims.get("type") != "refresh" or not claims.get("jti"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token.")
    if not db.consume_token(claims["jti"], claims["exp"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token already used.")
    if not db.get_user(claims["sub"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token.")
    return {**_issue_tokens(claims["sub"]), "user_id": claims["sub"]}


@router.get("/me")
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    if not credentials:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing Bearer authentication token.")
    valid, claims, err = security.decode_and_verify_token(credentials.credentials)
    if not valid or claims.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired access token.")
    user = db.get_user(claims["sub"])
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired access token.")
    return {"user_id": user["user_id"], "email": user["email"], "created_at": user["created_at"],
            "token_claims": claims}
