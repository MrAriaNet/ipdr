"""
Simple API-key authentication for IPDR / LEA endpoints.

Env:
  IPDR_API_KEYS=ops:KEY1,lea:KEY2,admin:KEY3
  IPDR_AUTH_REQUIRED=true|false  (default false for lab; true recommended in prod)

Roles:
  ops     — search / stats / dashboard APIs
  lea     — CGNAT lookup, investigate, export, AAA resolve
  admin   — collector control, retention purge, audit read
  collector — ingest only (netflow callback paths via local process; HTTP create)
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional, Set

from fastapi import Header, HTTPException, Request, status


ROLE_OPS = "ops"
ROLE_LEA = "lea"
ROLE_ADMIN = "admin"
ROLE_COLLECTOR = "collector"

# Higher roles inherit lower privileges
_ROLE_RANK = {
    ROLE_COLLECTOR: 1,
    ROLE_OPS: 2,
    ROLE_LEA: 3,
    ROLE_ADMIN: 4,
}


@dataclass
class AuthContext:
    role: str
    key_id: str
    authenticated: bool


def _parse_keys() -> dict:
    """
    IPDR_API_KEYS format: role:secret[,role:secret...]
    Example: admin:s3cret,lea:lea-key,ops:ops-key
    """
    raw = os.getenv("IPDR_API_KEYS", "").strip()
    out = {}
    if not raw:
        return out
    for part in raw.split(","):
        part = part.strip()
        if not part or ":" not in part:
            continue
        role, secret = part.split(":", 1)
        role = role.strip().lower()
        secret = secret.strip()
        if role in _ROLE_RANK and secret:
            out[secret] = role
    return out


def auth_required() -> bool:
    return os.getenv("IPDR_AUTH_REQUIRED", "false").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def role_allows(have: str, need: str) -> bool:
    return _ROLE_RANK.get(have, 0) >= _ROLE_RANK.get(need, 99)


def resolve_auth(
    request: Request,
    x_api_key: Optional[str] = None,
) -> AuthContext:
    keys = _parse_keys()
    required = auth_required()

    # Prefer header; also accept Authorization: Bearer <key>
    key = (x_api_key or "").strip()
    if not key:
        auth = request.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            key = auth[7:].strip()

    if not key:
        if not required:
            return AuthContext(role=ROLE_ADMIN, key_id="anonymous", authenticated=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key (X-API-Key or Authorization: Bearer)",
        )

    role = keys.get(key)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )
    return AuthContext(role=role, key_id=key[:6] + "…", authenticated=True)


def require_role(min_role: str):
    """FastAPI dependency factory."""

    async def _dep(
        request: Request,
        x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    ) -> AuthContext:
        ctx = resolve_auth(request, x_api_key)
        if not role_allows(ctx.role, min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{ctx.role}' cannot access this endpoint (need '{min_role}'+)",
            )
        return ctx

    return _dep
