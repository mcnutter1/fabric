"""Identity model, cookie sessions, and FastAPI auth dependencies."""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from itsdangerous import BadSignature, URLSafeTimedSerializer
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..models import NodeToken, Node
from . import mcnutt

_serializer = URLSafeTimedSerializer(settings.secret_key, salt="fabric-identity")


@dataclasses.dataclass
class Principal:
    uid: str
    username: str
    email: str
    name: str
    roles: list[str]

    @property
    def is_admin(self) -> bool:
        return any(r in settings.admin_roles for r in self.roles)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @staticmethod
    def from_payload(payload: dict) -> "Principal":
        identity = payload.get("identity", payload)
        return Principal(
            uid=identity.get("uid", ""),
            username=identity.get("username", ""),
            email=identity.get("email", ""),
            name=identity.get("name", ""),
            roles=payload.get("roles", []),
        )


def issue_session_cookie(principal: Principal) -> str:
    return _serializer.dumps(principal.to_dict())


def read_session_cookie(raw: str) -> Optional[Principal]:
    try:
        data = _serializer.loads(raw, max_age=settings.auth_ttl_sec)
    except BadSignature:
        return None
    except Exception:
        return None
    return Principal(**data)


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


async def get_current_user(request: Request) -> Optional[Principal]:
    """Resolve the operator identity from cookie or API key. Returns None if unauthenticated."""
    # 1. API key (server-to-server / CLI)
    auth_header = request.headers.get("authorization", "")
    api_key = ""
    if auth_header.lower().startswith("bearer "):
        api_key = auth_header[7:].strip()
    api_key = api_key or request.headers.get("x-api-key", "")
    if api_key and (api_key.startswith("mcak_") or api_key.startswith("mcsak_")):
        payload = await mcnutt.validate_api_key(api_key, _client_ip(request))
        if payload:
            return Principal.from_payload(payload)

    # 2. Session cookie
    raw = request.cookies.get(settings.auth_cookie_name)
    if raw:
        principal = read_session_cookie(raw)
        if principal:
            return principal

    # 3. Dev convenience — when running locally without SSO, act as a local admin.
    if settings.is_dev:
        return Principal(
            uid="local", username="local", email="admin@local",
            name="Local Admin", roles=list(settings.admin_roles) or ["admin"],
        )
    return None


async def require_user(
    principal: Optional[Principal] = Depends(get_current_user),
) -> Principal:
    if principal is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    return principal


async def require_admin(
    principal: Principal = Depends(require_user),
) -> Principal:
    if not principal.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin role required")
    return principal


# --- Node authentication (data-plane agents) ---

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def require_node(
    request: Request,
    db: Session = Depends(get_db),
) -> Node:
    """Authenticate a node agent by its long-lived bearer token."""
    auth_header = request.headers.get("authorization", "")
    token = ""
    if auth_header.lower().startswith("bearer "):
        token = auth_header[7:].strip()
    token = token or request.headers.get("x-node-token", "")
    if not token:
        raise HTTPException(status_code=401, detail="node token required")

    th = hash_token(token)
    nt = db.scalar(select(NodeToken).where(NodeToken.token_hash == th, NodeToken.revoked == False))  # noqa: E712
    if not nt:
        raise HTTPException(status_code=401, detail="invalid node token")
    node = db.get(Node, nt.node_id)
    if not node:
        raise HTTPException(status_code=401, detail="unknown node")
    return node
