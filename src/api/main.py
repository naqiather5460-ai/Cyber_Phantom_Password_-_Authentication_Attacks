import datetime
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from src.agent.authguard_agent import get_agent
from src.api.routes.auth import router as auth_router
from src.api.routes.telemetry import router as telemetry_router
from src.core.config import settings
from src.core.database import db
from src.core.middleware import RateLimitMiddleware, RequestTracingMiddleware, SecurityHeadersMiddleware

agent = get_agent()

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="""
## AuthGuard AI - Autonomous Authentication Attack Diagnosis & Adaptive Prevention

Detects and mitigates distributed credential stuffing, automated brute force (SSH/FTP Patator-style flows),
AI-assisted password guessing (via honeywords) and account takeover.

* **Dual ML engine** - calibrated HistGradientBoosting (network flow + behavioral RBA).
* **Graduated response** - Allow / Step-up MFA (TOTP) / Tarpit + Proof-of-Work / Block.
* **Timing-attack resistance** - PBKDF2 with dummy-hash work for unknown users.
""",
    version=settings.VERSION,
    docs_url=None if settings.IS_PRODUCTION else "/docs",
    redoc_url=None if settings.IS_PRODUCTION else "/redoc",
    openapi_url=None if settings.IS_PRODUCTION else "/openapi.json",
)

# Middleware runs bottom-to-top: CORS is outermost so even 429/500 responses carry CORS headers.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestTracingMiddleware)
app.add_middleware(RateLimitMiddleware, max_requests_per_minute=settings.RATE_LIMIT_GLOBAL_PER_MINUTE,
                   login_requests_per_minute=settings.RATE_LIMIT_LOGIN_PER_MINUTE)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID", "X-API-Key"],
    expose_headers=["X-Request-ID", "X-Response-Time-Ms", "Retry-After"],
)

app.include_router(auth_router, prefix=settings.API_PREFIX)
app.include_router(telemetry_router, prefix=settings.API_PREFIX)


@app.get("/health", tags=["Health & Readiness"])
@app.get("/api/v1/health", tags=["Health & Readiness"])
def health_check():
    """Liveness/readiness probe. Reports degraded when models or the database are unavailable."""
    db_ok = db.ping()
    models_ok = agent.network_loaded and agent.rba_loaded
    healthy = db_ok and models_ok
    payload = {
        "status": "healthy" if healthy else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "models": {
            "network_threat_engine_loaded": agent.network_loaded,
            "behavioral_rba_engine_loaded": agent.rba_loaded,
        },
        "database": "ok" if db_ok else "unreachable",
    }
    # A degraded dependency/model state must fail readiness probes instead of returning HTTP 200.
    return payload if healthy else JSONResponse(status_code=503, content=payload)


@app.get("/", tags=["Root"])
def root():
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "operational",
        "documentation": None if settings.IS_PRODUCTION else "/docs",
        "endpoints": {"auth": f"{settings.API_PREFIX}/auth", "telemetry": f"{settings.API_PREFIX}/telemetry",
                      "health": "/health"},
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
