"""
backend/routes/auth_routes.py
=============================
OPTIONAL authentication module.

===========================================================================
API CONTRACT
===========================================================================

POST /api/register
    Purpose        Create a local analyst account.
    Request        {username (3-64, [A-Za-z0-9_.-]), password (>= 8), role}
    Validation     Pydantic pattern + length; duplicate username -> 409.
    Auth           None (first-run registration). In production this endpoint
                   would be admin-only or disabled - noted in docs/SECURITY.md.
    Response 201   {message, detail}
    Errors         409 username taken, 422 validation error

POST /api/login
    Purpose        Exchange credentials for a signed bearer token.
    Request        {username, password}
    Validation     Constant-time PBKDF2 verification.
    Response 200   {access_token, token_type, expires_in, username, role}
    Errors         401 invalid credentials (identical message for unknown user
                   and wrong password, so the endpoint cannot be used to
                   enumerate accounts)

POST /api/logout
    Purpose        Revoke the presented token (added to an in-memory deny-list).
    Auth           Bearer token required.
    Response 200   {message}
    Errors         401 missing/invalid token

GET  /api/auth/status
    Purpose        Report whether authentication is enforced and how many users
                   exist. Used by the frontend to decide whether to show a
                   login form.
    Response 200   {require_auth, user_count, authenticated}

===========================================================================
HOW ENFORCEMENT WORKS
===========================================================================
``REQUIRE_AUTH`` (in .env) is FALSE by default so a student can run the
dashboard immediately. When set to TRUE, :func:`require_auth_if_enabled`
protects DELETE /api/analyses/{id}. The mechanism is fully implemented and
covered by automated tests in both states.
"""

from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Header, HTTPException, Request, status

from backend.config import settings
from backend.models import repository
from backend.models.schemas import LoginRequest, MessageResponse, RegisterRequest, TokenResponse
from backend.utils.logger import log_security_event
from backend.utils.security import (
    create_token,
    hash_password,
    revoke_token,
    verify_password,
    verify_token,
)

router = APIRouter(prefix="/api", tags=["Authentication (optional)"])


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def get_principal(authorization: str | None = Header(default=None)) -> dict | None:
    """Return the token payload when a valid bearer token is present, else ``None``."""
    token = _bearer(authorization)
    return verify_token(token) if token else None


def require_auth_if_enabled(authorization: str | None = Header(default=None)) -> dict | None:
    """Dependency: enforce authentication only when ``REQUIRE_AUTH`` is true."""
    principal = get_principal(authorization)
    if not settings.REQUIRE_AUTH:
        return principal
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Obtain a token from POST /api/login.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_auth(authorization: str | None = Header(default=None)) -> dict:
    """Dependency: always require a valid bearer token."""
    principal = get_principal(authorization)
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid bearer token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED,
             summary="Register a local analyst account")
def register(payload: RegisterRequest, request: Request):
    """Create a user with a salted PBKDF2-HMAC-SHA256 password hash."""
    try:
        user = repository.create_user(payload.username, hash_password(payload.password), payload.role)
    except sqlite3.IntegrityError:
        log_security_event("auth.register.duplicate", username=payload.username)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="That username is already registered.")
    log_security_event("auth.register.success", username=user["username"], role=user["role"])
    return {"message": "User registered.", "detail": user["username"]}


@router.post("/login", response_model=TokenResponse, summary="Log in and receive a bearer token")
def login(payload: LoginRequest, request: Request):
    """Verify credentials and issue a signed, expiring token."""
    user = repository.get_user(payload.username)
    if user is None or not verify_password(payload.password, user["password_hash"]):
        # Identical response for both failure modes -> no account enumeration.
        log_security_event("auth.login.failed", username=payload.username,
                           client=request.client.host if request.client else "unknown")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid username or password.",
                            headers={"WWW-Authenticate": "Bearer"})
    token, ttl = create_token(user["username"], user["role"])
    log_security_event("auth.login.success", username=user["username"], role=user["role"])
    return {"access_token": token, "token_type": "bearer", "expires_in": ttl,
            "username": user["username"], "role": user["role"]}


@router.post("/logout", response_model=MessageResponse, summary="Revoke the presented token")
def logout(authorization: str | None = Header(default=None)):
    """Add the token's unique id to the in-memory deny-list."""
    token = _bearer(authorization)
    if not token or not verify_token(token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing or invalid bearer token.",
                            headers={"WWW-Authenticate": "Bearer"})
    revoke_token(token)
    log_security_event("auth.logout")
    return {"message": "Logged out. Token revoked.", "detail": None}


@router.get("/auth/status", summary="Is authentication enforced?")
def auth_status(authorization: str | None = Header(default=None)):
    """Tell the frontend whether to show a login form."""
    principal = get_principal(authorization)
    return {
        "require_auth": settings.REQUIRE_AUTH,
        "user_count": repository.count_users(),
        "authenticated": principal is not None,
        "username": (principal or {}).get("sub"),
        "role": (principal or {}).get("role"),
        "note": ("Authentication is OPTIONAL in this student build. Set REQUIRE_AUTH=true in "
                 ".env to protect DELETE /api/analyses/{id}."),
    }
