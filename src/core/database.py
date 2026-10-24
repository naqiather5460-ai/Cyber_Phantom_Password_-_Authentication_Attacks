"""
AuthGuard AI - SQLite persistence layer (WAL mode).

Stores users, honeywords, audit logs, IP penalties, proof-of-work challenges,
single-use token ledger and per-user behavioral baselines. All state that must be
consistent across worker processes lives here, not in process memory.
"""

import json
import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from src.core.config import settings

_MAX_FIELD = 128


def _clip(value: Any) -> str:
    return str(value if value is not None else "")[:_MAX_FIELD]


class Database:
    def __init__(self, db_path: str = settings.DATABASE_PATH):
        self.db_path = db_path
        directory = os.path.dirname(self.db_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._init_db()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        """Commits on success, rolls back on error, and ALWAYS closes the connection."""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                mfa_secret TEXT,
                mfa_last_step INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS honeywords (
                user_id TEXT PRIMARY KEY,
                true_index INTEGER NOT NULL,
                word_hashes TEXT NOT NULL,
                created_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                timestamp REAL NOT NULL,
                user_id TEXT NOT NULL,
                ip_address TEXT, asn TEXT, country TEXT, city TEXT, browser TEXT, os TEXT,
                decision TEXT NOT NULL,
                risk_score REAL NOT NULL,
                threat_type TEXT NOT NULL,
                latency_ms REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(timestamp);
            CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_ip ON audit_logs(ip_address);
            CREATE TABLE IF NOT EXISTS ip_penalties (
                ip_address TEXT PRIMARY KEY,
                penalty_level INTEGER DEFAULT 0,
                consecutive_failures INTEGER DEFAULT 0,
                blocked_until REAL DEFAULT 0,
                pow_cleared_until REAL DEFAULT 0,
                last_seen REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pow_challenges (
                challenge_salt TEXT PRIMARY KEY,
                client_ip TEXT NOT NULL,
                difficulty INTEGER NOT NULL,
                created_at REAL NOT NULL,
                is_solved INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS token_ledger (
                jti TEXT PRIMARY KEY,
                attempts INTEGER NOT NULL DEFAULT 0,
                consumed INTEGER NOT NULL DEFAULT 0,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS user_baselines (
                user_id TEXT PRIMARY KEY,
                profile_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            );
            """)
            # Lightweight migrations for databases created by v1.0
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
            if "mfa_last_step" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN mfa_last_step INTEGER NOT NULL DEFAULT 0")
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(ip_penalties)")}
            if "pow_cleared_until" not in cols:
                conn.execute("ALTER TABLE ip_penalties ADD COLUMN pow_cleared_until REAL DEFAULT 0")

    # ------------------------------------------------------------------ users
    def create_user(self, user_id: str, email: str, password_hash: str, mfa_secret: Optional[str] = None) -> bool:
        try:
            with self._conn() as conn:
                conn.execute(
                    "INSERT INTO users (user_id, email, password_hash, mfa_secret, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, email.lower(), password_hash, mfa_secret, time.time()),
                )
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, identifier: str) -> Optional[Dict[str, Any]]:
        """Looks up by exact user_id first, then by (case-insensitive) email. Never ambiguous."""
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM users WHERE user_id = ?", (identifier,)).fetchone()
            if row is None:
                row = conn.execute("SELECT * FROM users WHERE email = ?", (identifier.lower(),)).fetchone()
            return dict(row) if row else None

    def user_or_email_exists(self, user_id: str, email: str) -> bool:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM users WHERE user_id = ? OR email = ? OR user_id = ? OR email = ? LIMIT 1",
                (user_id, email.lower(), email.lower(), user_id.lower()),
            ).fetchone()
            return row is not None

    def advance_mfa_step(self, user_id: str, step: int) -> bool:
        """Atomically records a used TOTP step; returns False if that step (or later) was already used."""
        with self._conn() as conn:
            cur = conn.execute(
                "UPDATE users SET mfa_last_step = ? WHERE user_id = ? AND mfa_last_step < ?",
                (step, user_id, step),
            )
            return cur.rowcount == 1

    # -------------------------------------------------------------- honeywords
    def store_honeywords(self, user_id: str, true_index: int, word_hashes: List[str]) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO honeywords (user_id, true_index, word_hashes, created_at) VALUES (?, ?, ?, ?)",
                (user_id, true_index, json.dumps(word_hashes), time.time()),
            )

    def get_honeywords(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM honeywords WHERE user_id = ?", (user_id,)).fetchone()
            if row:
                return {
                    "user_id": row["user_id"],
                    "true_index": row["true_index"],
                    "word_hashes": json.loads(row["word_hashes"]),
                    "created_at": row["created_at"],
                }
        return None

    # ------------------------------------------------------------------- audit
    def log_event(self, event: Dict[str, Any]) -> None:
        with self._conn() as conn:
            conn.execute(
                """INSERT INTO audit_logs (request_id, timestamp, user_id, ip_address, asn, country, city,
                   browser, os, decision, risk_score, threat_type, latency_ms)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    _clip(event.get("request_id")), time.time(), _clip(event.get("user_id") or "unknown"),
                    _clip(event.get("ip_address")), _clip(event.get("asn")), _clip(event.get("country")),
                    _clip(event.get("city")), _clip(event.get("browser")), _clip(event.get("os")),
                    _clip(event.get("decision") or "ALLOW"), float(event.get("risk_score", 0.0)),
                    _clip(event.get("threat_type") or "BENIGN_NORMAL_USER"), float(event.get("latency_ms", 0.0)),
                ),
            )

    def get_recent_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ----------------------------------------------------- IP penalty box / PoW
    def is_ip_blocked(self, ip: str) -> Dict[str, Any]:
        """Read-only check. (v1.0 called record_ip_attempt(success=True) here, which reset the failure
        counter on every request, so the penalty box could never trigger.)"""
        now = time.time()
        with self._conn() as conn:
            row = conn.execute("SELECT blocked_until FROM ip_penalties WHERE ip_address = ?", (ip,)).fetchone()
        blocked_until = row["blocked_until"] if row else 0
        return {"is_blocked": now < blocked_until, "retry_after": max(0, int(blocked_until - now))}

    def record_ip_failure(self, ip: str) -> Dict[str, Any]:
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM ip_penalties WHERE ip_address = ?", (ip,)).fetchone()
            if row is None:
                failures, penalty, blocked_until = 1, 0, 0.0
                conn.execute(
                    "INSERT INTO ip_penalties (ip_address, penalty_level, consecutive_failures, blocked_until, last_seen) "
                    "VALUES (?, 0, 1, 0, ?)", (ip, now))
            else:
                stale = now - row["last_seen"] > settings.IP_FAILURE_DECAY_SECONDS
                failures = 1 if stale else row["consecutive_failures"] + 1
                penalty = row["penalty_level"]
                blocked_until = row["blocked_until"]
                if failures >= settings.IP_FAILURE_THRESHOLD:
                    penalty += 1
                    blocked_until = now + 30 * (2 ** min(penalty, 5))   # 60s, 120s, ... capped at 16 min
                    failures = 0
                conn.execute(
                    "UPDATE ip_penalties SET penalty_level=?, consecutive_failures=?, blocked_until=?, last_seen=? "
                    "WHERE ip_address=?", (penalty, failures, blocked_until, now, ip))
        return {"is_blocked": now < blocked_until, "consecutive_failures": failures}

    def record_ip_success(self, ip: str) -> None:
        """A good login only reduces the counter by one, so an attacker cannot reset it by
        interleaving one valid credential pair between guesses."""
        with self._conn() as conn:
            conn.execute(
                "UPDATE ip_penalties SET consecutive_failures = MAX(consecutive_failures - 1, 0), last_seen = ? "
                "WHERE ip_address = ?", (time.time(), ip))

    def store_pow_challenge(self, salt: str, client_ip: str, difficulty: int) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute("DELETE FROM pow_challenges WHERE created_at < ?", (now - 3600,))
            conn.execute(
                "INSERT INTO pow_challenges (challenge_salt, client_ip, difficulty, created_at, is_solved) VALUES (?,?,?,?,0)",
                (salt, client_ip, difficulty, now))

    def consume_pow_challenge(self, salt: str, client_ip: str) -> Optional[int]:
        """Atomically marks an unexpired, unsolved challenge issued to this IP as solved.
        Returns its difficulty, or None if it is unknown / expired / already used / wrong IP."""
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT difficulty FROM pow_challenges WHERE challenge_salt=? AND client_ip=? AND is_solved=0 AND created_at>?",
                (salt, client_ip, now - settings.POW_TTL_SECONDS)).fetchone()
            if row is None:
                return None
            conn.execute("UPDATE pow_challenges SET is_solved=1 WHERE challenge_salt=?", (salt,))
            return int(row["difficulty"])

    def mark_pow_cleared(self, ip: str) -> None:
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO ip_penalties (ip_address, last_seen, pow_cleared_until) VALUES (?, ?, ?) "
                "ON CONFLICT(ip_address) DO UPDATE SET pow_cleared_until=excluded.pow_cleared_until",
                (ip, now, now + settings.POW_CLEARANCE_SECONDS))

    def is_pow_cleared(self, ip: str) -> bool:
        with self._conn() as conn:
            row = conn.execute("SELECT pow_cleared_until FROM ip_penalties WHERE ip_address=?", (ip,)).fetchone()
        return bool(row and row["pow_cleared_until"] > time.time())

    # ------------------------------------------------------------ token ledger
    def register_attempt(self, jti: str, expires_at: float, max_attempts: int) -> str:
        """Counts a verification attempt against a token. Returns 'ok', 'spent' (already used) or 'limit'."""
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM token_ledger WHERE expires_at < ?", (now,))
            row = conn.execute("SELECT attempts, consumed FROM token_ledger WHERE jti=?", (jti,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO token_ledger (jti, attempts, consumed, expires_at) VALUES (?,1,0,?)", (jti, expires_at))
                return "ok"
            if row["consumed"]:
                return "spent"
            if row["attempts"] >= max_attempts:
                return "limit"
            conn.execute("UPDATE token_ledger SET attempts = attempts + 1 WHERE jti=?", (jti,))
            return "ok"

    def consume_token(self, jti: str, expires_at: float) -> bool:
        """Single-use enforcement (MFA success, refresh-token rotation). False if already consumed."""
        now = time.time()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT consumed FROM token_ledger WHERE jti=?", (jti,)).fetchone()
            if row is None:
                conn.execute("INSERT INTO token_ledger (jti, attempts, consumed, expires_at) VALUES (?,0,1,?)", (jti, expires_at))
                return True
            if row["consumed"]:
                return False
            conn.execute("UPDATE token_ledger SET consumed=1 WHERE jti=?", (jti,))
            return True

    # --------------------------------------------------------- user baselines
    def save_baseline(self, user_id: str, profile: Dict[str, Any]) -> None:
        payload = {k: (sorted(v, key=str) if isinstance(v, (set, frozenset)) else v) for k, v in profile.items()}
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO user_baselines (user_id, profile_json, updated_at) VALUES (?,?,?)",
                (user_id, json.dumps(payload), time.time()))

    def get_baseline(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute("SELECT profile_json FROM user_baselines WHERE user_id=?", (user_id,)).fetchone()
        if not row:
            return None
        raw = json.loads(row["profile_json"])
        return {
            "asns": set(raw.get("asns", [])), "countries": set(raw.get("countries", [])),
            "cities": set(raw.get("cities", [])), "devices": set(raw.get("devices", [])),
            "browsers": set(raw.get("browsers", [])), "oss": set(raw.get("oss", [])),
            "rtts": list(raw.get("rtts", [])),
        }

    # -------------------------------------------------------------- SOC metrics
    def ping(self) -> bool:
        try:
            with self._conn() as conn:
                conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

    def get_soc_metrics(self) -> Dict[str, Any]:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
            prevented = conn.execute("SELECT COUNT(*) FROM audit_logs WHERE decision != 'ALLOW'").fetchone()[0]
            avg_latency = conn.execute("SELECT AVG(latency_ms) FROM audit_logs").fetchone()[0] or 0.0
            threats = {r["threat_type"]: r["c"] for r in conn.execute(
                "SELECT threat_type, COUNT(*) AS c FROM audit_logs GROUP BY threat_type")}
            decisions = {r["decision"]: r["c"] for r in conn.execute(
                "SELECT decision, COUNT(*) AS c FROM audit_logs GROUP BY decision")}
        return {
            "total_evaluations": total,
            "attacks_mitigated": prevented,
            "protection_rate_pct": round(prevented / total * 100, 2) if total else 0.0,
            "mean_latency_ms": round(avg_latency, 2),
            "threat_breakdown": threats,
            "decision_breakdown": decisions,
        }


db = Database()
