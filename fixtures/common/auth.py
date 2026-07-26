"""JWT authentication, shared by both fixture apps.

The credential is the only place a tenant identity may come from. Both apps
agree on that here; they disagree later about whether the *query* respects it,
which is exactly the bug class this project is about.

The token is a plain HS256 JWT with a fixture secret. It is not a model of good
key management and is not meant to be one — it is meant to be reproducible.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Annotated, Any, Literal

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

__all__ = [
    "DEFAULT_JWT_SECRET",
    "JWT_ALGORITHM",
    "Principal",
    "current_principal",
    "decode_token",
    "issue_token",
    "jwt_secret",
]

JWT_ALGORITHM = "HS256"

# A published constant, not a leaked one: the fixtures must be reproducible by
# anyone who clones the repo. Overridable via JWT_SECRET for the Compose setup.
#
# At least 32 bytes, because PyJWT warns below that for HS256 and a wall of
# warnings during a security tool's own test run trains people to ignore
# warnings — which is the last habit this project should be encouraging.
DEFAULT_JWT_SECRET = "fixture-only-never-use-this-secret-value"  # noqa: S105


def jwt_secret() -> str:
    """The signing secret, from ``JWT_SECRET`` or the fixture default."""
    return os.environ.get("JWT_SECRET") or DEFAULT_JWT_SECRET


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller, as carried by the token and nothing else."""

    user_id: str
    tenant_id: str
    tenant_label: str
    role: Literal["user", "admin"] = "user"

    @property
    def is_admin(self) -> bool:
        """True for platform administrators."""
        return self.role == "admin"


def issue_token(principal: Principal) -> str:
    """Sign a bearer token for ``principal``.

    Args:
        principal: The identity to encode.

    Returns:
        A compact HS256 JWT.
    """
    claims: dict[str, Any] = {
        "sub": principal.user_id,
        "tenant_id": principal.tenant_id,
        "tenant_label": principal.tenant_label,
        "role": principal.role,
    }
    return jwt.encode(claims, jwt_secret(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Principal:
    """Verify ``token`` and return the principal it names.

    Args:
        token: The compact JWT, without the ``Bearer`` prefix.

    Returns:
        The decoded :class:`Principal`.

    Raises:
        ValueError: If the signature, the algorithm, or a required claim is bad.
    """
    try:
        claims = jwt.decode(token, jwt_secret(), algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:  # bad signature, wrong alg, malformed token
        msg = f"invalid token: {exc}"
        raise ValueError(msg) from exc

    try:
        role = claims["role"]
        return Principal(
            user_id=str(claims["sub"]),
            tenant_id=str(claims["tenant_id"]),
            tenant_label=str(claims["tenant_label"]),
            role="admin" if role == "admin" else "user",
        )
    except KeyError as exc:
        msg = f"token is missing the {exc.args[0]!r} claim"
        raise ValueError(msg) from exc


# auto_error=False so a missing header reaches our own handler: FastAPI's
# built-in error for HTTPBearer is a 403, and the fixture contract says 401.
_bearer = HTTPBearer(auto_error=False, description="Bearer JWT issued by /api/signup")


async def current_principal(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
) -> Principal:
    """FastAPI dependency resolving the caller, or raising 401.

    Declared ``async`` deliberately: a sync dependency would be run on a worker
    thread with a *copy* of the context, and the safe app's global scope lives
    in a :class:`~contextvars.ContextVar` that must survive into the handler.
    """
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return decode_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]
"""Convenience alias so handlers read as ``principal: CurrentPrincipal``."""
