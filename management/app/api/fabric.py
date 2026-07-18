"""Fabric topology routes for the live map."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..database import get_db
from ..services.fabric import FabricOrchestrator

router = APIRouter(prefix="/fabric", tags=["fabric"])


@router.get("/topology")
def topology(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    return FabricOrchestrator(db).topology()


@router.post("/recompute")
def recompute(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    orch = FabricOrchestrator(db)
    orch.compute_links()
    return orch.topology()
