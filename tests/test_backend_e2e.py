"""
End-to-end backend tests (real HTTP stack via FastAPI TestClient).
Run:  python -m unittest discover -s tests -v
Uses a throw-away SQLite file and development-mode settings.
"""

import time
import unittest

from fastapi.testclient import TestClient  # noqa: E402

from src.api.main import app  # noqa: E402
from src.core.config import settings  # noqa: E402
from src.core.database import db  # noqa: E402
from src.core.security import security  # noqa: E402
from src.api.routes.auth import agent  # noqa: E402

API = settings.API_PREFIX
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36"
KEY = {"X-API-Key": settings.SERVICE_API_KEY}
_ip_counter = [10]


def fresh_ip():
    _ip_counter[0] += 1
    return f"198.51.100.{_ip_counter[0]}"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def register(self, suffix=""):
        n = f"{int(time.time() * 1000)}{suffix}{_ip_counter[0]}"
        _ip_counter[0] += 1
        body = {"email": f"User{n}@Example.com", "password": "ProductionPassword2024!", "user_id": f"user_{n}"}
        r = self.client.post(f"{API}/auth/register", json=body)
        self.assertEqual(r.status_code, 201, r.text)
        return {**body, **r.json()}

    def login(self, user, password=None, ip=None, headers=None, **extra):
        h = {"User-Agent": UA, "X-Forwarded-For": ip or fresh_ip(), **(headers or {})}
        payload = {"username": user["user_id"], "password": password or user["password"], **extra}
        return self.client.post(f"{API}/auth/login", json=payload, headers=h)

    def trusted_profile(self, user, **ctx):
        agent.rba_engine.learn_session(user["user_id"], {
            "asn": "29695", "country": "NO", "city": "Oslo", "device_type": "desktop",
            "browser": "Chrome", "os": "Windows", "rtt_ms": 35.0, **ctx})
        db.save_baseline(user["user_id"], agent.rba_engine.user_profiles[user["user_id"]])

    @staticmethod
    def totp(user):
        step = int(time.time() // 30)
        return security._hotp(user["mfa_secret"], step), step


class TestRegistration(Base):
    def test_registration_arms_honeywords_and_totp(self):
        u = self.register()
        self.assertEqual(u["honeywords_armed"], 5)
        self.assertTrue(u["mfa_provisioning_uri"].startswith("otpauth://totp/"))
        rec = db.get_honeywords(u["user_id"])
        self.assertEqual(len(rec["word_hashes"]), 6)
        stored = db.get_user(u["user_id"])
        self.assertTrue(stored["password_hash"].startswith("pbkdf2_sha256$"))
        self.assertEqual(stored["email"], stored["email"].lower())

    def test_duplicate_and_namespace_collision_rejected(self):
        u = self.register()
        r = self.client.post(f"{API}/auth/register", json={
            "email": "other@example.com", "password": "ProductionPassword2024!", "user_id": u["user_id"]})
        self.assertEqual(r.status_code, 409)
        # user_id may not contain '@' (would collide with another user's email on login lookup)
        r = self.client.post(f"{API}/auth/register", json={
            "email": "attacker@example.com", "password": "ProductionPassword2024!", "user_id": u["email"]})
        self.assertEqual(r.status_code, 422)

    def test_honeyword_decoys_are_not_typo_neighbours(self):
        from src.agent.deceptive_engine import DeceptiveDefenseEngine, _edit_distance
        eng = DeceptiveDefenseEngine()
        real = "Secur3P@ss2024!"
        decoys = eng._generate_realistic_decoys(real)
        self.assertEqual(len(set(decoys)), 5)
        for d in decoys:
            self.assertGreaterEqual(_edit_distance(d, real), 3)


class TestLoginFlow(Base):
    def test_known_context_allows_and_jwt_is_valid(self):
        u = self.register()
        self.trusted_profile(u)
        r = self.login(u, asn="29695", country="NO", city="Oslo", rtt_ms=35.0)
        self.assertIn(r.json()["decision"], ("ALLOW", "STEP_UP_CHALLENGE"), r.text)
        if r.json()["decision"] == "ALLOW":
            ok, claims, _ = security.decode_and_verify_token(r.json()["access_token"])
            self.assertTrue(ok)
            me = self.client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
            self.assertEqual(me.json()["user_id"], u["user_id"])

    def test_wrong_password_is_denied_without_user_enumeration(self):
        u = self.register()
        r1 = self.login(u, password="WrongPassword!1")
        r2 = self.client.post(f"{API}/auth/login", json={"username": "nobody_here", "password": "WrongPassword!1"},
                              headers={"User-Agent": UA, "X-Forwarded-For": fresh_ip()})
        self.assertEqual(r1.status_code, r2.status_code)
        self.assertEqual(r1.json()["detail"], r2.json()["detail"])

    def test_first_login_new_device_requires_mfa_then_becomes_trusted(self):
        u = self.register()
        r = self.login(u, asn="64500", country="PK", city="Karachi", rtt_ms=60.0)
        body = r.json()
        self.assertEqual(body["decision"], "STEP_UP_CHALLENGE", r.text)
        # a wrong code is rejected (v1.0 accepted ANY 6-digit code)
        bad = self.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "mfa_code": "000000"})
        self.assertEqual(bad.status_code, 401)
        code, _ = self.totp(u)
        good = self.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "mfa_code": code})
        self.assertEqual(good.status_code, 200, good.text)
        ok, claims, _ = security.decode_and_verify_token(good.json()["access_token"])
        self.assertTrue(claims["mfa_verified"])
        # the verified context is now baseline
        prof = db.get_baseline(u["user_id"])
        self.assertIn("Karachi", prof["cities"])

    def test_mfa_token_is_single_use_and_code_not_replayable(self):
        u = self.register()
        body = self.login(u, asn="64500", country="PK", city="Karachi").json()
        code, _ = self.totp(u)
        first = self.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "mfa_code": code})
        self.assertEqual(first.status_code, 200)
        replay = self.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "mfa_code": code})
        self.assertEqual(replay.status_code, 401)

    def test_mfa_attempts_are_limited(self):
        u = self.register()
        body = self.login(u, asn="64500", country="PK", city="Karachi").json()
        statuses = [self.client.post(f"{API}/auth/mfa/verify",
                                     json={"mfa_token": body["mfa_token"], "mfa_code": "111111"},
                                     headers={"X-Forwarded-For": fresh_ip()}).status_code for _ in range(7)]
        self.assertEqual(statuses[-1], 429)
        code, _ = self.totp(u)   # even the right code no longer works on a burnt token
        self.assertEqual(self.client.post(f"{API}/auth/mfa/verify",
                         json={"mfa_token": body["mfa_token"], "mfa_code": code}).status_code, 429)

    def test_refresh_token_rotation(self):
        u = self.register()
        body = self.login(u, asn="64500", country="PK", city="Karachi").json()
        code, _ = self.totp(u)
        tokens = self.client.post(f"{API}/auth/mfa/verify", json={"mfa_token": body["mfa_token"], "mfa_code": code}).json()
        r1 = self.client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self.assertEqual(r1.status_code, 200)
        r2 = self.client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
        self.assertEqual(r2.status_code, 401)
        # an access token cannot be used as a refresh token
        r3 = self.client.post(f"{API}/auth/refresh", json={"refresh_token": tokens["access_token"]})
        self.assertEqual(r3.status_code, 401)


class TestDeceptionAndAbuse(Base):
    def test_honeyword_trips_and_survives_restart(self):
        u = self.register()
        decoy = agent.deception_engine.register_user_credentials(u["user_id"], u["password"])["decoys"][0]
        rec = agent.deception_engine.honeychecker_store[u["user_id"]]
        db.store_honeywords(u["user_id"], rec["true_index"], rec["word_hashes"])
        agent.deception_engine.honeychecker_store.clear()            # simulate fresh worker / restart
        r = self.login(u, password=decoy, asn="AS9009", country="RU")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["threat_type"], "HONEYWORD_DATABASE_LEAK_EXPLOITATION")
        self.assertTrue(r.json()["access_token"].startswith("canary_quarantine_"))
        me = self.client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
        self.assertEqual(me.status_code, 401)

    def test_ip_penalty_box_actually_blocks(self):
        """v1.0 reset the failure counter on every request, so this never triggered."""
        u = self.register()
        ip = fresh_ip()
        codes = [self.login(u, password="WrongPassword!1", ip=ip).status_code for _ in range(settings.IP_FAILURE_THRESHOLD)]
        self.assertNotIn(403, codes)
        blocked = self.login(u, ip=ip)       # even the correct password is refused while blocked
        self.assertEqual(blocked.status_code, 403)
        self.assertIn("Retry-After", blocked.headers)

    def test_spoofed_client_telemetry_is_ignored_unless_trusted(self):
        """Attacker with stolen credentials claims the victim's usual device/network in the JSON body."""
        u = self.register()
        self.trusted_profile(u)
        claims = dict(asn="29695", country="NO", city="Oslo", rtt_ms=35.0,
                      device_type="desktop", browser="Chrome 122", os="Windows 11")
        bot_ua = {"User-Agent": "curl/8.5.0"}
        old = settings.TRUST_CLIENT_TELEMETRY
        try:
            settings.TRUST_CLIENT_TELEMETRY = False                      # production behaviour
            r = self.login(u, headers=bot_ua, **claims)
            self.assertNotEqual(r.json()["decision"], "ALLOW", r.text)   # real UA/network wins over the claims
            latest = db.get_recent_audit_logs(1)[0]
            self.assertEqual(latest["country"], "XX")                    # claimed 'NO' was discarded
            gw = self.login(u, headers={**bot_ua, **KEY}, **claims)      # gateway-injected values are honoured
            self.assertEqual(db.get_recent_audit_logs(1)[0]["country"], "NO")
            self.assertIn(gw.json()["decision"], ("ALLOW", "STEP_UP_CHALLENGE"))
        finally:
            settings.TRUST_CLIENT_TELEMETRY = old

    def test_forwarded_header_ignored_unless_proxy_trusted(self):
        self.assertEqual(security.extract_client_ip({"x-forwarded-for": "1.2.3.4"}, "9.9.9.9", trust_proxy=False), "9.9.9.9")
        self.assertEqual(security.extract_client_ip({"x-forwarded-for": "6.6.6.6, 1.2.3.4"}, "9.9.9.9", trust_proxy=True), "1.2.3.4")


class TestProofOfWork(Base):
    def _solve(self, ch):
        n = 0
        while not security.verify_pow_solution(ch["challenge_salt"], str(n), ch["difficulty"]):
            n += 1
        return n

    def test_pow_is_server_issued_single_use_ip_bound_and_relaxes_tarpit(self):
        ip = fresh_ip()
        ch = security.generate_pow_challenge(ip, settings.POW_DIFFICULTY)
        nonce = self._solve(ch)
        # a self-minted challenge (never issued by the server) is rejected
        r = self.client.post(f"{API}/auth/pow/verify", json={"challenge_salt": ch["challenge_salt"], "nonce": str(nonce)},
                             headers={"X-Forwarded-For": ip})
        self.assertEqual(r.status_code, 400)
        # a server-issued one works once, from the same IP only
        db.store_pow_challenge(ch["challenge_salt"], ip, ch["difficulty"])
        wrong_ip = self.client.post(f"{API}/auth/pow/verify", json={"challenge_salt": ch["challenge_salt"], "nonce": str(nonce)},
                                    headers={"X-Forwarded-For": fresh_ip()})
        self.assertEqual(wrong_ip.status_code, 400)
        ok = self.client.post(f"{API}/auth/pow/verify", json={"challenge_salt": ch["challenge_salt"], "nonce": str(nonce)},
                              headers={"X-Forwarded-For": ip})
        self.assertEqual(ok.status_code, 200, ok.text)
        again = self.client.post(f"{API}/auth/pow/verify", json={"challenge_salt": ch["challenge_salt"], "nonce": str(nonce)},
                                 headers={"X-Forwarded-For": ip})
        self.assertEqual(again.status_code, 400)
        self.assertTrue(db.is_pow_cleared(ip))

    def test_tarpit_issues_persisted_challenge(self):
        u = self.register()
        r = self.login(u, password="WrongPassword!1", asn="393398", country="US", city="Unknown",
                       device_type="bot", browser="HeadlessChrome", os="Linux", rtt_ms=350.0)
        if r.json()["decision"] == "TARPIT_THROTTLE":
            salt = r.json()["pow_challenge"]["challenge_salt"]
            self.assertEqual(r.status_code, 429)
            self.assertIsNotNone(db.consume_pow_challenge(salt, r.request.headers["X-Forwarded-For"]))


class TestTelemetryAccessControl(Base):
    def test_all_telemetry_endpoints_require_api_key(self):
        for method, path in [("get", "/telemetry/soc-overview"), ("get", "/telemetry/audit-logs"),
                             ("get", "/telemetry/user-risk-profile/someone")]:
            self.assertEqual(getattr(self.client, method)(f"{API}{path}").status_code, 401, path)
            self.assertEqual(getattr(self.client, method)(f"{API}{path}", headers={"X-API-Key": "wrong"}).status_code, 401)
        self.assertEqual(self.client.post(f"{API}/telemetry/evaluate", json={}).status_code, 401)

    def test_soc_and_audit_with_key(self):
        u = self.register()
        self.login(u, password="WrongPassword!1")
        ov = self.client.get(f"{API}/telemetry/soc-overview", headers=KEY).json()
        self.assertGreaterEqual(ov["total_evaluations"], 1)
        logs = self.client.get(f"{API}/telemetry/audit-logs?limit=5", headers=KEY).json()
        self.assertGreaterEqual(logs["count"], 1)
        self.assertIn("request_id", logs["audit_logs"][0])

    def test_external_evaluate(self):
        r = self.client.post(f"{API}/telemetry/evaluate", headers=KEY, json={
            "user_id": "ext_user", "password_candidate": "x", "rtt_ms": None})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIn("decision", r.json())


class TestPlatform(Base):
    def test_health_and_headers(self):
        r = self.client.get("/health")
        self.assertEqual(r.json()["status"], "healthy")
        self.assertEqual(r.headers["x-content-type-options"], "nosniff")
        self.assertNotIn("x-xss-protection", r.headers)

    def test_request_id_is_sanitised(self):
        r = self.client.get("/health", headers={"X-Request-ID": "bad id\r\nX-Evil: 1"})
        self.assertNotIn("evil", r.headers.get("x-request-id", "").lower())

    def test_swagger_ui_csp_allows_assets(self):
        r = self.client.get("/docs")
        self.assertEqual(r.status_code, 200)
        self.assertIn("cdn.jsdelivr.net", r.headers["content-security-policy"])

    def test_jwt_expiry_is_strict(self):
        expired = security.create_jwt_token({"sub": "expired-user", "type": "access"}, -1)
        valid, claims, _ = security.decode_and_verify_token(expired)
        self.assertFalse(valid)
        self.assertIsNone(claims)

    def test_password_verifier_rejects_unbounded_or_malformed_records(self):
        self.assertFalse(security.verify_password("anything", "pbkdf2_sha256$999999999$00$00"))
        self.assertFalse(security.verify_password("anything", "pbkdf2_sha256$200000$00$00"))

    def test_totp_matches_rfc6238_vector(self):
        # RFC 6238 Appendix B (SHA-1), T=59 -> 94287082; our 6-digit form is the last 6 digits
        secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"   # base32 of "12345678901234567890"
        self.assertEqual(security._hotp(secret, 59 // 30, digits=8), "94287082")
        self.assertEqual(security.verify_totp(secret, "287082", now=59), 59 // 30)
        self.assertIsNone(security.verify_totp(secret, "000000", now=59))


if __name__ == "__main__":
    unittest.main()
