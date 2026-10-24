"""Seeds dummy users and risk evaluations, then prints the SOC overview. Dev only."""
import json
import urllib.request, urllib.error

BASE = "http://127.0.0.1:8000/api/v1"
API_KEY = "devtestkey123"   # must match $env:AUTHGUARD_API_KEY used to start the server


def call(method, path, body=None, key=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("X-API-Key", API_KEY)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


print("== Registering dummy users ==")
users = {}
for i in range(1, 4):
    uid = f"dummy_user{i}"
    pw = f"DummyPass{i}23!"
    code, r = call("POST", "/auth/register",
                   {"email": f"{uid}@example.com", "password": pw, "user_id": uid})
    note = r.get("status") or r.get("detail")
    print(f"  {uid}: HTTP {code} {note}")
    users[uid] = pw

print("\n== Risk evaluations (telemetry/evaluate) ==")
scenarios = [
    ("Normal login, familiar context", "dummy_user1", "DummyPass123!",
     {"asn": "AS15169", "country": "US", "city": "New York", "device_type": "desktop", "browser": "Chrome", "os": "Windows"}),
    ("Wrong password (login_successful=0)", "dummy_user1", "not-the-password", {"login_successful": 0}),
    ("Foreign country, new device", "dummy_user2", "DummyPass223!",
     {"asn": "AS4134", "country": "CN", "city": "Beijing", "device_type": "mobile", "browser": "Firefox", "os": "Android", "rtt_ms": 320}),
    ("Bot-like client, very low latency", "dummy_user3", "DummyPass323!",
     {"asn": "AS14061", "country": "RU", "city": "Moscow", "device_type": "bot", "browser": "curl", "os": "Linux", "rtt_ms": 1}),
    ("Foreign + failed login", "dummy_user2", "wrong-guess",
     {"asn": "AS14061", "country": "RU", "city": "Moscow", "device_type": "bot", "browser": "curl", "os": "Linux", "rtt_ms": 1, "login_successful": 0}),
    ("Demo user, normal credentials", "sarah_connor", "SkynetKiller2024!", {}),
]
for name, uid, pw, ctx in scenarios:
    body = {"user_id": uid, "password_candidate": pw, "ip_address": "192.0.2.10", **ctx}
    code, r = call("POST", "/telemetry/evaluate", body, key=True)
    print(f"  {name}: HTTP {code} -> {r.get('decision')} | risk {r.get('risk_score')} | {r.get('threat_type')}")

print("\n== SOC overview ==")
code, r = call("GET", "/telemetry/soc-overview", key=True)
print(" ", code, json.dumps(r, indent=2))

print("\n== Last 5 audit log entries ==")
code, r = call("GET", "/telemetry/audit-logs?limit=5", key=True)
for e in r.get("audit_logs", []):
    print(f"  {e['user_id']:<14} {e['decision']:<18} risk={e['risk_score']} {e['threat_type']}")

print("\n== Risk profile of dummy_user1 ==")
code, r = call("GET", "/telemetry/user-risk-profile/dummy_user1", key=True)
print(" ", code, json.dumps(r))

print("\n== API key check (no key, should be 401) ==")
code, r = call("GET", "/telemetry/soc-overview")
print(" ", code)
