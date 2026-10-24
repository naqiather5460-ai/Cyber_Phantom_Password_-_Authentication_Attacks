"""
AuthGuard AI - Pydantic request & response schemas.
Strict types, patterns and length limits on every attacker-reachable field.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

USER_ID_PATTERN = r"^[A-Za-z0-9_.-]{3,64}$"   # no '@': keeps user_id and email namespaces disjoint


class UserRegisterRequest(BaseModel):
    email: EmailStr = Field(..., examples=["alice@example.com"])
    password: str = Field(..., min_length=8, max_length=128, description="Plaintext password to register")
    user_id: Optional[str] = Field(None, pattern=USER_ID_PATTERN, examples=["alice_sec"])

    @field_validator("email")
    @classmethod
    def _lower_email(cls, v: str) -> str:
        return v.lower()


class UserRegisterResponse(BaseModel):
    user_id: str
    email: str
    status: str
    honeywords_armed: int
    mfa_secret: str = Field(..., description="Base32 TOTP secret. Shown once - display as QR/enrolment key.")
    mfa_provisioning_uri: str
    created_at: float


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128, examples=["alice@example.com"])
    password: str = Field(..., min_length=1, max_length=128)
    # Client-reported context. IGNORED unless AUTHGUARD_TRUST_CLIENT_TELEMETRY=true or the request
    # carries the service API key (i.e. was injected by your own gateway/BFF).
    asn: Optional[str] = Field(None, max_length=32, examples=["AS15169"])
    country: Optional[str] = Field(None, max_length=8, examples=["US"])
    city: Optional[str] = Field(None, max_length=64, examples=["Los Angeles"])
    rtt_ms: Optional[float] = Field(None, ge=1.0, le=5000.0, examples=[45.2])
    device_type: Optional[str] = Field(None, max_length=16, examples=["desktop"])
    browser: Optional[str] = Field(None, max_length=64, examples=["Chrome 122.0"])
    os: Optional[str] = Field(None, max_length=64, examples=["Windows 11"])
    # Network flow metrics - honoured only from the gateway (service API key).
    network_flow: Optional[Dict[str, float]] = None

    @field_validator("network_flow")
    @classmethod
    def _bounded_flow(cls, v):
        if v is not None and len(v) > 64:
            raise ValueError("network_flow may contain at most 64 features")
        return v


class LoginSuccessResponse(BaseModel):
    decision: str = "ALLOW"
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user_id: str
    risk_score: float
    threat_type: str
    latency_ms: float


class LoginChallengeResponse(BaseModel):
    decision: str
    mfa_token: Optional[str] = None
    supported_methods: Optional[List[str]] = None
    pow_challenge: Optional[Dict[str, Any]] = None
    delay_seconds: float = 0.0
    risk_score: float
    threat_type: str
    detail: str
    latency_ms: float


class MFAVerifyRequest(BaseModel):
    mfa_token: str = Field(..., max_length=2048, description="Temporary MFA token issued during step-up")
    mfa_code: str = Field(..., pattern=r"^\d{6}$", examples=["123456"], description="6-digit TOTP code")


class RefreshRequest(BaseModel):
    refresh_token: str = Field(..., max_length=2048)


class POWVerifyRequest(BaseModel):
    challenge_salt: str = Field(..., min_length=8, max_length=64)
    nonce: str = Field(..., min_length=1, max_length=32, pattern=r"^\d+$")
    user_id: Optional[str] = Field(None, max_length=128)


class RiskEvaluationRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=128)
    password_candidate: str = Field(..., min_length=1, max_length=128)
    ip_address: Optional[str] = Field("127.0.0.1", max_length=64)
    asn: Optional[str] = Field("AS15169", max_length=32)
    country: Optional[str] = Field("US", max_length=8)
    city: Optional[str] = Field("New York", max_length=64)
    device_type: Optional[str] = Field("desktop", max_length=16)
    browser: Optional[str] = Field("Chrome", max_length=64)
    os: Optional[str] = Field("Windows", max_length=64)
    rtt_ms: Optional[float] = Field(45.0, ge=0.0, le=60000.0)
    login_successful: Optional[int] = Field(1, ge=0, le=1)
    network_flow: Optional[Dict[str, float]] = None


class RiskEvaluationResponse(BaseModel):
    user_id: str
    decision: str
    risk_score: float
    threat_type: str
    mitigation: Dict[str, Any]
    latency_ms: float
    risk_breakdown: Dict[str, Any]


class SOCOverviewResponse(BaseModel):
    total_evaluations: int
    attacks_mitigated: int
    protection_rate_pct: float
    mean_latency_ms: float
    threat_breakdown: Dict[str, int]
    decision_breakdown: Dict[str, int]
