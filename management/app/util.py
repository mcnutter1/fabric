"""Small shared utilities."""
from __future__ import annotations

import datetime as dt
import secrets
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from .models import AuditLog


def new_id(prefix: str = "") -> str:
    core = uuid.uuid4().hex[:24]
    return f"{prefix}{core}" if prefix else core


def gen_token(prefix: str = "fabtok_", nbytes: int = 32) -> str:
    return prefix + secrets.token_urlsafe(nbytes)


def gen_pairing_code() -> str:
    # human-friendly, unambiguous
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def audit(db: Session, *, actor: str, actor_type: str, action: str,
          target: str = "", detail: Optional[dict] = None, ip: str = "") -> None:
    db.add(AuditLog(
        actor=actor, actor_type=actor_type, action=action,
        target=target, detail=detail or {}, ip=ip,
    ))
    db.commit()
