"""
AuthGuard AI - Central Configuration & Environment Settings.

Secrets are NEVER hard-coded. In production (AUTHGUARD_ENV=production) the service
refuses to start unless real secrets are supplied. In development, ephemeral random
secrets are generated per process (tokens do not survive a restart).
"""

import os
import secrets
import sys
from typing import List


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: List[str]) -> List[str]:
    raw = os.getenv(name)
    if not raw:
        return default
    return [item.strip() for item in raw.split(",") if item.strip()]


class Settings:
    PROJECT_NAME: str = "AuthGuard AI - Enterprise Authentication Security Engine"
    VERSION: str = "1.1.0"
    API_PREFIX: str = "/api/v1"

    ENV: str = os.getenv("AUTHGUARD_ENV", "development").strip().lower()
    IS_PRODUCTION: bool = ENV == "production"

    # --- Secrets -----------------------------------------------------------------
    SECRET_KEY: str = os.getenv("AUTHGUARD_SECRET_KEY", "")
    SERVICE_API_KEY: str = os.getenv("AUTHGUARD_API_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MFA_TOKEN_EXPIRE_MINUTES: int = 5
    MFA_MAX_ATTEMPTS: int = 5

    # --- Network trust -----------------------------------------------------------
    # Only honour X-Forwarded-For / CF-Connecting-IP when running behind a proxy you control.
    TRUST_PROXY_HEADERS: bool = _env_bool("AUTHGUARD_TRUST_PROXY_HEADERS", False)
    # Browser-supplied asn/country/city/rtt are attacker-controlled. Only trusted in dev,
    # or when the request carries the service API key (i.e. injected by your gateway/BFF).
    TRUST_CLIENT_TELEMETRY: bool = _env_bool("AUTHGUARD_TRUST_CLIENT_TELEMETRY", not IS_PRODUCTION)

    CORS_ORIGINS: List[str] = _env_list(
        "AUTHGUARD_CORS_ORIGINS",
        [
            "http://localhost:3000",
            "http://localhost:3001",
            "http://localhost:5173",
            "http://localhost:8080",
            "http://127.0.0.1:3000",
            "http://127.0.0.1:5173",
        ],
    )

    DATABASE_PATH: str = os.getenv("AUTHGUARD_DB_PATH", "var/authguard.db")

    # --- Rate limiting & tarpit --------------------------------------------------
    RATE_LIMIT_LOGIN_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_LOGIN", "25"))
    RATE_LIMIT_GLOBAL_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_GLOBAL", "150"))
    TARPIT_DELAY_SECONDS: float = float(os.getenv("AUTHGUARD_TARPIT_DELAY", "3.5"))
    HONEYWORDS_COUNT: int = 5
    POW_DIFFICULTY: int = 4          # leading hex zeros
    POW_TTL_SECONDS: int = 180
    POW_CLEARANCE_SECONDS: int = 600  # how long a solved PoW relaxes the tarpit for that IP

    # IP penalty box
    IP_FAILURE_THRESHOLD: int = 5
    IP_FAILURE_DECAY_SECONDS: int = 900

    # Demo data (sarah_connor). Never enable in production.
    SEED_DEMO_USER: bool = _env_bool("AUTHGUARD_SEED_DEMO_USER", False)

    def __init__(self) -> None:
        if not self.SECRET_KEY:
            if self.IS_PRODUCTION:
                sys.exit("FATAL: AUTHGUARD_SECRET_KEY must be set in production.")
            self.SECRET_KEY = secrets.token_urlsafe(48)
        if not self.SERVICE_API_KEY:
            if self.IS_PRODUCTION:
                sys.exit("FATAL: AUTHGUARD_API_KEY must be set in production.")
            self.SERVICE_API_KEY = "dev-" + secrets.token_urlsafe(24)
        if len(self.SECRET_KEY) < 32:
            if self.IS_PRODUCTION:
                sys.exit("FATAL: AUTHGUARD_SECRET_KEY must be at least 32 characters.")
        if self.IS_PRODUCTION and self.SEED_DEMO_USER:
            sys.exit("FATAL: AUTHGUARD_SEED_DEMO_USER must not be enabled in production.")
        if self.IS_PRODUCTION and "*" in self.CORS_ORIGINS:
            sys.exit("FATAL: wildcard CORS origin is not allowed in production.")


settings = Settings()
