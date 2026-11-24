"""Admin panel accounts, password hashing, sessions and login lockout.

- Passwords are hashed with scrypt (Python standard library) and a random salt.
- The browser gets a random session token in an httpOnly cookie; the database
  keeps only its SHA-256, so a copy of the database cannot be used to log in.
- Too many wrong passwords from one address lock that address out for a while.
"""

import base64
import hashlib
import hmac
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta

from app import config
from app.services.database import get_connection

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
MIN_PASSWORD_LENGTH = 12


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def hash_password(password: str) -> str:
    """Return 'scrypt:N:r:p:salt:hash' (no '$', so it is safe in env files)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )
    return f"scrypt:{SCRYPT_N}:{SCRYPT_R}:{SCRYPT_P}:{_b64(salt)}:{_b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split(":")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode("utf-8"), salt=_unb64(salt), n=int(n), r=int(r), p=int(p),
            dklen=len(_unb64(digest)),
        )
        return hmac.compare_digest(candidate, _unb64(digest))
    except (ValueError, TypeError):
        return False


# A fixed hash used to spend the same time when the username is unknown.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def _now() -> datetime:
    return datetime.now(UTC)


# ---------- accounts ----------


def ensure_bootstrap_admin() -> None:
    """Create the first admin from settings if that account does not exist yet."""
    if not (config.ADMIN_USER and config.ADMIN_PASSWORD_HASH):
        return
    if not config.ADMIN_PASSWORD_HASH.startswith("scrypt:"):
        return
    db = get_connection()
    now = _now().isoformat()
    with db:
        db.execute(
            "INSERT OR IGNORE INTO admin_users (username, password_hash, created_at, password_changed_at) "
            "VALUES (?, ?, ?, ?)",
            (config.ADMIN_USER, config.ADMIN_PASSWORD_HASH, now, now),
        )


def set_password(username: str, password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
    db = get_connection()
    now = _now().isoformat()
    with db:
        db.execute(
            "INSERT INTO admin_users (username, password_hash, created_at, password_changed_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT(username) DO UPDATE SET "
            "password_hash = excluded.password_hash, password_changed_at = excluded.password_changed_at",
            (username, hash_password(password), now, now),
        )
        # Changing a password logs out every other session for that account.
        db.execute("DELETE FROM admin_sessions WHERE username = ?", (username,))


def check_credentials(username: str, password: str) -> str | None:
    """Return the stored username if the password is right, else None."""
    row = get_connection().execute(
        "SELECT username, password_hash FROM admin_users WHERE username = ?", (username.strip(),)
    ).fetchone()
    if row is None:
        verify_password(password, _DUMMY_HASH)
        return None
    return row["username"] if verify_password(password, row["password_hash"]) else None


# ---------- sessions ----------


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    now = _now()
    db = get_connection()
    with db:
        db.execute("DELETE FROM admin_sessions WHERE expires_at < ?", (now.isoformat(),))
        db.execute(
            "INSERT INTO admin_sessions (token_hash, username, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (
                _token_hash(token),
                username,
                now.isoformat(),
                (now + timedelta(days=config.ADMIN_SESSION_DAYS)).isoformat(),
            ),
        )
    return token


def session_user(token: str | None) -> str | None:
    if not token or len(token) > 200:
        return None
    row = get_connection().execute(
        "SELECT s.username FROM admin_sessions s JOIN admin_users u ON u.username = s.username "
        "WHERE s.token_hash = ? AND s.expires_at > ?",
        (_token_hash(token), _now().isoformat()),
    ).fetchone()
    return row["username"] if row else None


def end_session(token: str | None) -> None:
    if not token:
        return
    db = get_connection()
    with db:
        db.execute("DELETE FROM admin_sessions WHERE token_hash = ?", (_token_hash(token),))


# ---------- login lockout (memory only) ----------


class LoginLimiter:
    def __init__(self):
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def _recent(self, key: str, now: float) -> list[float]:
        window = config.LOGIN_LOCK_MINUTES * 60
        times = [t for t in self._failures.get(key, []) if now - t < window]
        if times:
            self._failures[key] = times
        else:
            self._failures.pop(key, None)
        return times

    def retry_after(self, key: str) -> int:
        """Seconds until this address may try again (0 = allowed)."""
        now = time.time()
        with self._lock:
            times = self._recent(key, now)
            if len(times) < config.LOGIN_MAX_FAILURES:
                return 0
            return int(config.LOGIN_LOCK_MINUTES * 60 - (now - times[0])) + 1

    def failed(self, key: str) -> None:
        with self._lock:
            self._failures.setdefault(key, []).append(time.time())

    def succeeded(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._failures.clear()


limiter = LoginLimiter()
