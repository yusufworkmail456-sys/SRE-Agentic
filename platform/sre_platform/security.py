"""Security primitives: agent tokens, RBAC dependency, secret encryption."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db
from .models import Server, User

ROLE_ORDER = {"viewer": 0, "responder": 1, "owner": 2, "admin": 3}


def new_agent_token() -> str:
    return f"sreag_{secrets.token_urlsafe(32)}"


def hash_token(token: str) -> str:
    """Tokens are stored hashed — a DB dump must not yield fleet credentials."""
    return hashlib.sha256(token.encode()).hexdigest()


def hash_password(password: str) -> str:
    """PBKDF2-SHA256 with per-password salt (Django-style encoding)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 390_000).hex()
    return f"pbkdf2_sha256$390000${salt}${digest}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        _scheme, _iters, salt, digest = encoded.split("$", 3)
    except ValueError:
        return False
    check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 390_000).hex()
    return hmac.compare_digest(check, digest)


def _fernet(key_material: str) -> Fernet:
    digest = hashlib.sha256(key_material.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_secret(plaintext: str, key_material: str) -> str:
    return _fernet(key_material).encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str, key_material: str) -> str:
    try:
        return _fernet(key_material).decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("cannot decrypt secret (wrong key)") from exc


def mask(secret: str) -> str:
    return f"{secret[:6]}…{secret[-4:]}" if len(secret) > 12 else "***"


def agent_server(
    authorization: str | None = Header(default=None), db: Session = Depends(get_db)
) -> Server:
    """Authenticate an agent request by bearer token -> Server row."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing agent token")
    token = authorization.removeprefix("Bearer ").strip()
    server = db.scalar(select(Server).where(Server.token_hash == hash_token(token)))
    if server is None or not hmac.compare_digest(server.token_hash or "", hash_token(token)):
        raise HTTPException(401, "invalid agent token")
    return server


def require_role(minimum: str = "viewer"):
    """RBAC gate for UI/API routes (spec §27). Session auth wired in M5."""

    def _dep(db: Session = Depends(get_db), user: str | None = Header(default=None, alias="X-User")):
        if user is None:
            if minimum == "viewer":
                return None  # read-only access allowed pre-auth in MVP
            raise HTTPException(401, "authentication required")
        row = db.scalar(select(User).where(User.username == user, User.active == True))  # noqa: E712
        if row is None or ROLE_ORDER.get(row.role, -1) < ROLE_ORDER[minimum]:
            raise HTTPException(403, f"requires role {minimum}")
        return row

    return _dep
