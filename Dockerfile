FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 AUTHGUARD_ENV=production

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only what the API needs at runtime: code + trained models. The 92 MB training CSV and docs stay out
# of the image (see .dockerignore); mutable state lives in the /app/var volume.
COPY src/ ./src/
COPY models/ ./models/

RUN useradd --system --uid 10001 --home /app authguard \
    && mkdir -p /app/var && chown -R authguard:authguard /app/var
USER authguard

EXPOSE 8000
VOLUME ["/app/var"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

# One worker by default: the in-memory rate limiter is per process. Scale with replicas behind a gateway,
# or raise --workers if you accept per-worker limits (all durable state is in SQLite and is worker-safe).
CMD ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
