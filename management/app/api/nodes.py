"""Node management routes (operator-facing)."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..config import settings
from ..database import get_db
from ..models import Node, PairingCode
from ..models.enums import NodeStatus
from ..schemas import NodeCreate, NodeUpdate, NodeOut, PairingOut
from ..services.fabric import FabricOrchestrator
from ..services.wireguard import AddressAllocator
from ..util import new_id, gen_pairing_code, gen_token, utcnow, audit

router = APIRouter(prefix="/nodes", tags=["nodes"])


def _allocate_fabric_addr(db: Session) -> str:
    used = {n.fabric_addr for n in db.scalars(select(Node)) if n.fabric_addr}
    return AddressAllocator(settings.node_cidr).allocate(used)


@router.get("", response_model=list[NodeOut])
def list_nodes(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    return list(db.scalars(select(Node).order_by(Node.name)))


@router.post("", response_model=NodeOut, status_code=201)
def create_node(body: NodeCreate, request: Request, db: Session = Depends(get_db),
                admin: Principal = Depends(require_admin)):
    if db.scalar(select(Node).where(Node.name == body.name)):
        raise HTTPException(409, "node name already exists")
    node = Node(
        id=new_id("node_"),
        name=body.name,
        roles=body.roles,
        region=body.region,
        status=NodeStatus.pending.value,
        fabric_addr=_allocate_fabric_addr(db),
        wg_listen_port=settings.wg_port,
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    FabricOrchestrator(db).compute_links()
    audit(db, actor=admin.email, actor_type="user", action="node.create", target=node.id)
    return node


@router.get("/{node_id}", response_model=NodeOut)
def get_node(node_id: str, db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    return node


@router.patch("/{node_id}", response_model=NodeOut)
def update_node(node_id: str, body: NodeUpdate, db: Session = Depends(get_db),
                admin: Principal = Depends(require_admin)):
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    for field, value in body.model_dump(exclude_unset=True).items():
        setattr(node, field, value)
    db.commit()
    db.refresh(node)
    audit(db, actor=admin.email, actor_type="user", action="node.update", target=node.id)
    return node


@router.delete("/{node_id}", status_code=204)
def delete_node(node_id: str, db: Session = Depends(get_db), admin: Principal = Depends(require_admin)):
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    db.delete(node)
    db.commit()
    audit(db, actor=admin.email, actor_type="user", action="node.delete", target=node_id)


@router.post("/{node_id}/pair", response_model=PairingOut)
def issue_pairing(node_id: str, db: Session = Depends(get_db), admin: Principal = Depends(require_admin)):
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    # Invalidate previous unused codes.
    for pc in db.scalars(select(PairingCode).where(PairingCode.node_id == node_id, PairingCode.used_at.is_(None))):
        pc.used_at = utcnow()
    code = gen_pairing_code()
    pairing = PairingCode(
        code=code,
        node_id=node_id,
        expires_at=utcnow() + dt.timedelta(minutes=30),
        enrollment_secret=gen_token("enroll_"),
    )
    db.add(pairing)
    node.status = NodeStatus.pairing.value
    db.commit()
    audit(db, actor=admin.email, actor_type="user", action="node.pair", target=node_id)
    base = settings.public_url.rstrip("/")
    # One-liner: downloads the bundle straight from the mgmt plane, enrols, pairs.
    install_cmd = f"wget -qO- {base}/i/{code} | sudo bash"
    return PairingOut(code=code, expires_at=pairing.expires_at, install_command=install_cmd)


@router.post("/{node_id}/update", response_model=NodeOut)
def request_update(node_id: str, db: Session = Depends(get_db),
                   admin: Principal = Depends(require_admin)):
    """Flag a node to self-update (git pull + restart) on its next heartbeat."""
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    node.meta = {**(node.meta or {}), "update_requested": True}
    db.commit()
    db.refresh(node)
    audit(db, actor=admin.email, actor_type="user", action="node.update_requested", target=node_id)
    return node


@router.get("/{node_id}/config")
def node_config(node_id: str, db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    """Preview the computed data-plane config for a node (operator view)."""
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    return FabricOrchestrator(db).compute_node_config(node)
