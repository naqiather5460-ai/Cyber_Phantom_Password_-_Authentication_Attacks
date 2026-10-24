"""Test environment - executed before any test module imports application settings."""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="authguard_test_")
os.environ["AUTHGUARD_DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["AUTHGUARD_ENV"] = "development"
os.environ["AUTHGUARD_TRUST_PROXY_HEADERS"] = "true"   # tests give every request its own X-Forwarded-For
os.environ["AUTHGUARD_TARPIT_DELAY"] = "0"
os.environ["RATE_LIMIT_LOGIN"] = "1000"
os.environ["RATE_LIMIT_GLOBAL"] = "10000"
