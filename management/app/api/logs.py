"""Activity / audit log routes (operator-facing).

Surfaces the AuditLog trail that every mutating action already writes, so the
console has a single place to see who/what changed across the fabric.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc, or_
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..database import get_db
from ..models import AuditLog

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("")
def list_logs(db: Session = Depends(get_db), _: Principal = Depends(require_admin),
              limit: int = Query(200, le=2000), actor_type: str = "",
              action: str = "", target: str = "", q: str = ""):
    """Recent activity, newest first. Optional filters by actor type, action
    prefix, target id, or a free-text match across actor/action/target."""
    stmt = select(AuditLog).order_by(desc(AuditLog.ts))
    if actor_type:
        stmt = stmt.where(AuditLog.actor_type == actor_type)
    if action:
        stmt = stmt.where(AuditLog.action.like(f"{action}%"))
    if target:
        stmt = stmt.where(AuditLog.target == target)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(
            AuditLog.actor.like(like),
            AuditLog.action.like(like),
            AuditLog.target.like(like),
        ))
    rows = db.scalars(stmt.limit(limit))
    return [
        {
            "id": r.id, "ts": r.ts, "actor": r.actor, "actor_type": r.actor_type,
            "action": r.action, "target": r.target, "detail": r.detail or {}, "ip": r.ip,
        }
        for r in rows
    ]
