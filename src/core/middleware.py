"""
AuthGuard AI - Security middleware.
Secure headers, request tracing (sanitised correlation IDs), per-IP sliding-window rate limiting,
and RFC 7807 sanitised 500s.
"""

import re
import time
import uuid
from collections import deque
from typing import Deque, Dict, Tuple

from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from src.core.config import settings
from src.core.security import security

_DOC_PATHS = ("/docs", "/redoc", "/openapi.json")
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Cache-Control"] = "no-store"
        if request.url.path.startswith(_DOC_PATHS):
            # Swagger UI / ReDoc load assets from jsDelivr; the strict API policy would render a blank page.
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "worker-src blob:; frame-ancestors 'none'")
        else:
            response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response


class RequestTracingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        supplied = request.headers.get("X-Request-ID", "")
        request_id = supplied if _REQUEST_ID_RE.match(supplied) else uuid.uuid4().hex
        request.state.request_id = request_id
        try:
            response: Response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - start) * 1000
            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "type": "https://authguard.ai/errors/internal-server-error",
                    "title": "Internal Server Error", "status": 500,
                    "detail": "An internal error occurred. Please reference the request ID when contacting security operations.",
                    "request_id": request_id, "latency_ms": round(duration_ms, 2)},
                headers={"X-Request-ID": request_id})
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(round((time.perf_counter() - start) * 1000, 2))
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Per-process sliding-window limiter, keyed by (client IP, bucket). Login gets a tighter bucket.
    NOTE: state is per worker process; with N workers the effective limit is up to N x the configured
    value. Use your gateway / Redis for a hard global limit. The durable per-IP penalty box lives in SQLite.
    """
    _MAX_TRACKED_KEYS = 50_000

    def __init__(self, app, max_requests_per_minute: int = settings.RATE_LIMIT_GLOBAL_PER_MINUTE,
                 login_requests_per_minute: int = settings.RATE_LIMIT_LOGIN_PER_MINUTE):
        super().__init__(app)
        self.max_requests = max_requests_per_minute
        self.login_max = login_requests_per_minute
        self.windows: Dict[Tuple[str, str], Deque[float]] = {}
        self._last_sweep = time.time()

    def _sweep(self, now: float) -> None:
        if now - self._last_sweep < 60 and len(self.windows) < self._MAX_TRACKED_KEYS:
            return
        self._last_sweep = now
        for key in [k for k, q in self.windows.items() if not q or now - q[-1] > 60]:
            del self.windows[key]

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.endswith("/health"):
            return await call_next(request)

        headers = {k.lower(): v for k, v in request.headers.items()}
        ip = security.extract_client_ip(headers, request.client.host if request.client else "127.0.0.1")
        bucket, limit = ("login", self.login_max) if path.endswith("/auth/login") else ("global", self.max_requests)

        now = time.time()
        self._sweep(now)
        window = self.windows.setdefault((ip, bucket), deque())
        while window and now - window[0] >= 60.0:
            window.popleft()
        if len(window) >= limit:
            retry_after = max(1, 60 - int(now - window[0]))
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"type": "https://authguard.ai/errors/rate-limit-exceeded", "title": "Too Many Requests",
                         "status": 429, "detail": "Rate limit exceeded. Too many requests from this IP address.",
                         "retry_after_seconds": retry_after},
                headers={"Retry-After": str(retry_after)})
        window.append(now)
        return await call_next(request)
