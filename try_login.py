import base64, hashlib, hmac, json, struct, time
import urllib.request, urllib.error

BASE = "http://127.0.0.1:8000/api/v1"
SECRET = "JBSWY3DPEHPK3PXP"   


def call(method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def totp(secret):
    key = base64.b32decode(secret)
    h = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10**6).zfill(6)


print("1) Login")
code, r = call("POST", "/auth/login", {"username": "sarah_connor", "password": "SkynetKiller2024!"})
print("  ", code, r.get("decision"), r.get("threat_type"))

print("2) MFA verify")
code, r = call("POST", "/auth/mfa/verify", {"mfa_token": r["mfa_token"], "mfa_code": totp(SECRET)})
print("  ", code, r.get("decision"))
token = r["access_token"]

print("3) /auth/me with token")
code, r = call("GET", "/auth/me", token=token)
print("  ", code, r.get("user_id"), r.get("email"))

print("4) /auth/me without token (should be 401)")
code, r = call("GET", "/auth/me")
print("  ", code)

print("5) Wrong password (should be DENIED)")
code, r = call("POST", "/auth/login", {"username": "sarah_connor", "password": "wrong"})
print("  ", code, r.get("decision"), r.get("threat_type"))
