"""
Deceptive Defense Engine (Honeywords & Canary Tokens)
Inspired by Juels & Rivest (2013).

Design notes (v1.1):
* Sweetword hashes are keyed + slow (PBKDF2-HMAC-SHA256 with a server-side pepper), not bare SHA-256.
  A leaked table of unsalted fast hashes lets an attacker crack every sweetword offline and sort out
  the real one, which defeats the whole scheme.
* Decoys are kept at edit-distance >= 3 from the real password. Pure "year+1" / "!->@" tweaks are exactly
  the typos a legitimate user makes and would raise false canary alarms against real customers.
* Comparison scans every sweetword in constant time.
"""

import hashlib
import hmac
import re
import secrets
import string
from typing import Dict, List, Optional

from src.core.config import settings

_MIN_EDIT_DISTANCE = 3
_ITERATIONS = 10_000   # ~10 ms; the server-side pepper (not iteration count) is what blocks offline cracking of a leaked table


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class DeceptiveDefenseEngine:
    def __init__(self, num_honeywords: int = 5, pepper: Optional[str] = None):
        self.k = num_honeywords
        self._pepper = (pepper or settings.SECRET_KEY).encode("utf-8")
        # In production the honeychecker should live in a separate, tightly-permissioned service/DB.
        self.honeychecker_store: Dict[str, dict] = {}

    # ------------------------------------------------------------------ hashing
    def _hash_word(self, user_id: str, word: str) -> str:
        salt = hmac.new(self._pepper, b"honey-salt:" + user_id.encode("utf-8"), hashlib.sha256).digest()
        return hashlib.pbkdf2_hmac("sha256", word.encode("utf-8"), salt, _ITERATIONS).hex()

    def dummy_work(self) -> None:
        """Burns the same CPU as a real check so unknown usernames are not distinguishable by timing."""
        self._hash_word("dummy-user", "dummy-password")

    # ------------------------------------------------------------------ decoys
    def _generate_realistic_decoys(self, real_password: str) -> List[str]:
        decoys: List[str] = []

        def _add(candidate: str) -> None:
            if (candidate and candidate != real_password and candidate not in decoys
                    and len(decoys) < self.k
                    and _edit_distance(candidate, real_password) >= _MIN_EDIT_DISTANCE):
                decoys.append(candidate)

        year = re.search(r"(19\d\d|20\d\d)", real_password)
        stem = real_password.rstrip(string.punctuation + string.digits) or real_password
        symbols = ["!", "@", "#", "$", "?", "123", "!@#", "2026"]
        leet = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}

        def leeted(word: str) -> str:
            for ch, sub in leet.items():
                if ch in word.lower():
                    return re.sub(ch, sub, word, count=1, flags=re.IGNORECASE)
            return word

        flipped = (real_password[0].swapcase() + real_password[1:]) if real_password else real_password

        variants = []
        if year:
            for offset in (3, -3, 5, -4, 7):                       # distance >= 3 on the year alone is rare
                y = str(int(year.group(0)) + offset)
                variants.append(real_password[:year.start()] + y + real_password[year.end():])
                for sym in symbols[:4]:
                    variants.append(real_password[:year.start()] + y + sym)
        for sym in symbols:
            variants.append(stem + sym)
            variants.append(flipped.rstrip(string.punctuation) + sym + "1")
            variants.append(leeted(stem) + sym)
        for variant in variants:
            _add(variant)

        # Guaranteed fallback: random human-looking suffixes (large edit distance by construction)
        while len(decoys) < self.k:
            suffix = secrets.choice(["Pass", "Qwerty", "Admin", "Welcome", "Login"]) + str(secrets.randbelow(9000) + 1000)
            _add(f"{stem}{suffix}")
        return decoys[: self.k]

    # --------------------------------------------------------------- registration
    def register_user_credentials(self, user_id: str, real_password: str) -> dict:
        decoys = self._generate_realistic_decoys(real_password)
        all_words = decoys + [real_password]
        secrets.SystemRandom().shuffle(all_words)
        true_index = all_words.index(real_password)
        self.honeychecker_store[user_id] = {
            "true_index": true_index,
            "word_hashes": [self._hash_word(user_id, w) for w in all_words],
        }
        return {"user_id": user_id, "sweetwords_count": len(all_words), "decoys": decoys, "status": "honeywords_armed"}

    def hydrate(self, user_id: str, record: Optional[dict]) -> None:
        """Loads a persisted honeychecker record (so state survives restarts / is shared by workers)."""
        if record:
            self.honeychecker_store[user_id] = {
                "true_index": record["true_index"], "word_hashes": list(record["word_hashes"])}

    # ------------------------------------------------------------------ checking
    def verify_attempt(self, user_id: str, candidate_password: str) -> dict:
        record = self.honeychecker_store.get(user_id)
        if record is None:
            self.dummy_work()
            return {"result": "UNKNOWN_USER", "is_honeyword": False, "valid": False}

        candidate = self._hash_word(user_id, candidate_password)
        matched_index = -1
        for idx, stored in enumerate(record["word_hashes"]):       # no early exit
            if hmac.compare_digest(stored, candidate):
                matched_index = idx

        if matched_index < 0:
            return {"result": "INVALID_PASSWORD", "is_honeyword": False, "valid": False}
        if matched_index == record["true_index"]:
            return {"result": "AUTHENTICATED", "is_honeyword": False, "valid": True}
        return {
            "result": "HONEYWORD_TRIPPED", "is_honeyword": True, "valid": False,
            "alarm": "CRITICAL_DATABASE_OR_DICTIONARY_COMPROMISE_DETECTED",
        }
