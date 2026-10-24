"""
AuthGuard AI - Enterprise Security & Cryptography Primitives
Provides timing-attack-resistant PBKDF2 password hashing, RFC 7519 JWT implementation,
cryptographic Proof-of-Work (PoW) verification, and client telemetry extraction.
"""

import hmac
import hashlib
import secrets
import base64
import json
import time
import struct
import uuid
from typing import Optional, Dict, Any, Tuple
from src.core.config import settings

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def _b64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if (len(data) % 4) != 0 else ''
    return base64.urlsafe_b64decode((data + padding).encode('utf-8'))

class SecurityEngine:
    # ---------------------------------------------------------
    # 1. NIST SP 800-63B Compliant Password Hashing & Timing Protection
    # ---------------------------------------------------------
    @staticmethod
    def hash_password(password: str, iterations: int = 200_000) -> str:
        """
        Hashes password with PBKDF2-HMAC-SHA256 and a random 16-byte cryptographic salt.
        Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
        """
        salt = secrets.token_bytes(16)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        return f"pbkdf2_sha256${iterations}${salt.hex()}${key.hex()}"

    @staticmethod
    def verify_password(plain_password: str, hashed_record: str) -> bool:
        """
        Constant-time password comparison immune to side-channel timing attacks.
        """
        try:
            parts = hashed_record.split('$')
            if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
                return False
            iterations = int(parts[1])
            salt = bytes.fromhex(parts[2])
            expected_hash = bytes.fromhex(parts[3])
            # Stored records are database-controlled, but malformed/corrupt records must not
            # be able to request unbounded CPU work during a public login attempt.
            if not 100_000 <= iterations <= 2_000_000 or len(salt) != 16 or len(expected_hash) != 32:
                return False

            computed_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), salt, iterations)
            return hmac.compare_digest(computed_hash, expected_hash)
        except Exception:
            return False

    # ---------------------------------------------------------
    # 2. RFC 7519 Compliant JSON Web Token (JWT) Engine
    # ---------------------------------------------------------
    @staticmethod
    def create_jwt_token(payload: Dict[str, Any], expires_seconds: int) -> str:
        """
        Generates a signed JWT token using HMAC-SHA256.
        """
        now = int(time.time())
        header = {"alg": "HS256", "typ": "JWT"}
        claims = payload.copy()
        claims["iat"] = now
        claims["exp"] = now + expires_seconds
        claims["jti"] = uuid.uuid4().hex
        
        header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        claims_b64 = _b64url_encode(json.dumps(claims, separators=(',', ':')).encode('utf-8'))
        
        signing_input = f"{header_b64}.{claims_b64}".encode('utf-8')
        signature = hmac.new(settings.SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        signature_b64 = _b64url_encode(signature)
        
        return f"{header_b64}.{claims_b64}.{signature_b64}"

    @staticmethod
    def decode_and_verify_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """
        Decodes token and performs strict cryptographic signature & expiration checks.
        Returns: (is_valid, claims, error_message)
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return False, None, "Malformed token structure"
            
            header_b64, claims_b64, signature_b64 = parts
            header = json.loads(_b64url_decode(header_b64).decode('utf-8'))
            # Never accept algorithm negotiation or unexpected token header types.
            if not isinstance(header, dict) or header.get("alg") != "HS256" or header.get("typ") != "JWT":
                return False, None, "Unsupported token header"
            signing_input = f"{header_b64}.{claims_b64}".encode('utf-8')
            expected_sig = hmac.new(settings.SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
            provided_sig = _b64url_decode(signature_b64)
            
            if not hmac.compare_digest(expected_sig, provided_sig):
                return False, None, "Invalid cryptographic signature"
                
            claims = json.loads(_b64url_decode(claims_b64).decode('utf-8'))
            now = int(time.time())
            
            if not isinstance(claims, dict):
                return False, None, "Malformed token claims"
            exp = claims.get("exp")
            if not isinstance(exp, (int, float)) or isinstance(exp, bool) or exp <= now:
                return False, None, "Token has expired"
                
            return True, claims, ""
        except Exception as e:
            return False, None, "Malformed token"

    # ---------------------------------------------------------
    # 3. Cryptographic Proof-of-Work (PoW) Engine (Tarpit Defense)
    # ---------------------------------------------------------
    @staticmethod
    def generate_pow_challenge(client_ip: str, difficulty: int = 4) -> Dict[str, Any]:
        # NOTE: callers must persist the challenge (db.store_pow_challenge) so that it can be
        # verified once, before expiry, from the same IP.
        """
        Generates a cryptographic puzzle for suspected botnets.
        Requires client to find a nonce such that:
        SHA256(challenge_salt + nonce) starts with '0' * difficulty
        """
        challenge_salt = secrets.token_hex(16)
        timestamp = int(time.time())
        return {
            "challenge_salt": challenge_salt,
            "difficulty": difficulty,
            "target_prefix": "0" * difficulty,
            "timestamp": timestamp,
            "expires_in_seconds": settings.POW_TTL_SECONDS,
            "algorithm": "SHA-256"
        }

    @staticmethod
    def verify_pow_solution(challenge_salt: str, nonce: str, difficulty: int = 4) -> bool:
        """
        Validates client-side proof-of-work solution in under 0.1ms.
        """
        if not isinstance(nonce, str) or len(nonce) > 32 or not nonce.isdigit():
            return False
        test_str = f"{challenge_salt}:{nonce}".encode('utf-8')
        digest = hashlib.sha256(test_str).hexdigest()
        return digest.startswith("0" * difficulty)

    # ---------------------------------------------------------
    # 4. Telemetry & Client Extraction Helpers
    # ---------------------------------------------------------
    @staticmethod
    def extract_client_ip(headers: Dict[str, str], client_host: str, trust_proxy: Optional[bool] = None) -> str:
        """
        Returns the client IP. Proxy headers are attacker-controlled unless the service sits
        behind a proxy you control, so they are ignored unless AUTHGUARD_TRUST_PROXY_HEADERS=true.
        """
        trust = settings.TRUST_PROXY_HEADERS if trust_proxy is None else trust_proxy
        if trust:
            if headers.get("cf-connecting-ip"):
                return headers["cf-connecting-ip"].strip()[:64]
            if headers.get("x-forwarded-for"):
                # Right-most entry was appended by OUR proxy; left-most is client-controlled.
                parts = [p.strip() for p in headers["x-forwarded-for"].split(',') if p.strip()]
                if parts:
                    return parts[-1][:64]
            if headers.get("x-real-ip"):
                return headers["x-real-ip"].strip()[:64]
        return (client_host or "127.0.0.1")[:64]

    @staticmethod
    def is_service_key(provided: Optional[str]) -> bool:
        """Constant-time check of the backend-to-backend API key."""
        if not provided:
            return False
        return hmac.compare_digest(provided.encode('utf-8'), settings.SERVICE_API_KEY.encode('utf-8'))

    # ---------------------------------------------------------
    # 5. RFC 6238 TOTP (stdlib only)
    # ---------------------------------------------------------
    @staticmethod
    def generate_totp_secret() -> str:
        """160-bit random secret, base32 encoded (the format authenticator apps expect)."""
        return base64.b32encode(secrets.token_bytes(20)).decode('ascii')

    @staticmethod
    def totp_uri(secret: str, account: str, issuer: str = "AuthGuard AI") -> str:
        from urllib.parse import quote
        return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}"

    @staticmethod
    def _hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
        key = base64.b32decode(secret_b32.strip().upper() + '=' * (-len(secret_b32.strip()) % 8))
        digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code).zfill(digits)

    @staticmethod
    def verify_totp(secret_b32: str, code: str, window: int = 1, step_seconds: int = 30,
                    now: Optional[float] = None) -> Optional[int]:
        """Returns the matched time-step counter (for replay protection) or None."""
        if not secret_b32 or not isinstance(code, str) or not (code.isdigit() and len(code) == 6):
            return None
        try:
            current = int((now if now is not None else time.time()) // step_seconds)
            matched: Optional[int] = None
            for delta in range(-window, window + 1):   # always scan every slot (constant work)
                step = current + delta
                if hmac.compare_digest(SecurityEngine._hotp(secret_b32, step), code):
                    matched = step
            return matched
        except Exception:
            return None


security = SecurityEngine()
