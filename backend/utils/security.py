"""
backend/utils/security.py
=========================
PURPOSE
-------
Security primitives used by the API:

  * password hashing               (PBKDF2-HMAC-SHA256, salted, 200 000 rounds)
  * stateless signed tokens        (HMAC-SHA256 over a base64url payload)
  * token revocation ("logout")    (in-memory deny-list)
  * a simple fixed-window rate limiter

WHY NO EXTERNAL CRYPTO LIBRARY?
-------------------------------
The whole project must install with ``pip install -r requirements.txt`` on a
student laptop and run offline. ``hashlib``/``hmac``/``secrets`` are part of the
standard library and implement exactly the primitives needed here. For a
production system you would use a vetted library (``passlib[bcrypt]`` or
``argon2-cffi``) and a proper session/JWT library - that trade-off is recorded
in docs/SECURITY.md.

WHAT IS DELIBERATELY SAFE HERE
------------------------------
* passwords are never logged, never returned and never stored in clear text,
* every hash uses a fresh 16-byte salt,
* verification uses ``hmac.compare_digest`` (constant time),
* the token signature is verified before the payload is trusted,
* tokens expire (``TOKEN_TTL_SECONDS``),
* the rate limiter is per-client-IP and per-endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Any, Deque, Dict, Optional, Tuple

from backend.config import settings

PBKDF2_ROUNDS = 200_000
SALT_BYTES = 16


# ---------------------------------------------------------------------------
# Password hashing
# ---------------------------------------------------------------------------
def hash_password(password: str) -> str:
    """Return ``pbkdf2_sha256$rounds$salt_b64$hash_b64``."""
    salt = secrets.token_bytes(SALT_BYTES)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return "$".join([
        "pbkdf2_sha256",
        str(PBKDF2_ROUNDS),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    ])


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of a password against a stored hash."""
    try:
        algorithm, rounds_s, salt_b64, hash_b64 = stored.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds_s))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Signed tokens
# ---------------------------------------------------------------------------
def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


_REVOKED: set[str] = set()
_REVOKED_LOCK = threading.Lock()


def create_token(username: str, role: str = "analyst", ttl: Optional[int] = None) -> Tuple[str, int]:
    """Create a signed, expiring token. Returns ``(token, expires_in_seconds)``."""
    ttl = int(ttl if ttl is not None else settings.TOKEN_TTL_SECONDS)
    payload = {
        "sub": username,
        "role": role,
        "iat": int(time.time()),
        "exp": int(time.time()) + ttl,
        "jti": secrets.token_urlsafe(12),
    }
    body = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(settings.SECRET_KEY.encode("utf-8"), body.encode("ascii"),
                         hashlib.sha256).digest()
    return f"{body}.{_b64url_encode(signature)}", ttl


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify signature + expiry + revocation. Returns the payload or ``None``."""
    if not token or "." not in token:
        return None
    body, _, sig = token.partition(".")
    try:
        expected = hmac.new(settings.SECRET_KEY.encode("utf-8"), body.encode("ascii"),
                            hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url_decode(sig), expected):
            return None
        payload = json.loads(_b64url_decode(body))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    with _REVOKED_LOCK:
        if payload.get("jti") in _REVOKED:
            return None
    return payload


def revoke_token(token: str) -> bool:
    """Add a token's id to the in-memory deny-list (logout)."""
    payload = verify_token(token)
    if not payload:
        return False
    with _REVOKED_LOCK:
        _REVOKED.add(payload.get("jti", ""))
    return True


def clear_revocations() -> None:
    """Test helper - empty the deny-list."""
    with _REVOKED_LOCK:
        _REVOKED.clear()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
class RateLimiter:
    """Fixed-window, in-memory rate limiter keyed by ``(client_ip, bucket)``.

    Suitable for a single-process student deployment. A multi-worker production
    deployment needs a shared store (Redis) or a gateway-level limit - noted in
    docs/SECURITY.md.
    """

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max(1, int(max_requests))
        self.window = max(1, int(window_seconds))
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str) -> Tuple[bool, int, int]:
        """Return ``(allowed, remaining, retry_after_seconds)``."""
        now = time.time()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.max_requests:
                retry_after = int(self.window - (now - bucket[0])) + 1
                return False, 0, max(1, retry_after)
            bucket.append(now)
            return True, self.max_requests - len(bucket), 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def configure(self, max_requests: int, window_seconds: int) -> None:
        """Reconfigure at runtime (used by the rate-limit test)."""
        with self._lock:
            self.max_requests = max(1, int(max_requests))
            self.window = max(1, int(window_seconds))
            self._hits.clear()


#: Shared limiter instance for the analysis endpoints.
analysis_limiter = RateLimiter(settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW_SECONDS)
