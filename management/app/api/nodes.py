"""Node management routes (operator-facing)."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from sqlalchemy import select, desc, func, or_
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..config import settings
from ..database import get_db
from ..models import Node, PairingCode, FabricLink, Endpoint, FlowRecord
from ..models.enums import NodeStatus, NodeRole
from ..schemas import NodeCreate, NodeUpdate, NodeOut, PairingOut
from ..services.fabric import FabricOrchestrator
from ..services.wireguard import AddressAllocator
from ..services.dns import Route53Service
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
    # Best-effort DNS cleanup for the auto-provisioned hostname.
    if node.hostname and node.public_endpoint:
        Route53Service().delete_a(node.hostname, node.public_endpoint.split(":")[0])
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


@router.post("/update-all")
def request_update_all(online: bool = Query(False), db: Session = Depends(get_db),
                       admin: Principal = Depends(require_admin)):
    """Flag every node (or only online ones) to self-update on next heartbeat.

    Returns the set of nodes that were flagged so a CLI/console can track the
    rollout and report per-node results as heartbeats come back in."""
    q = select(Node)
    if online:
        q = q.where(Node.status == NodeStatus.online.value)
    nodes = list(db.scalars(q.order_by(Node.name)))
    now = int(utcnow().timestamp())
    flagged = []
    for node in nodes:
        upd = dict((node.meta or {}).get("update") or {})
        upd.update({"state": "requested", "requested_at": now, "from_version": node.version})
        node.meta = {**(node.meta or {}), "update_requested": True, "update": upd}
        flagged.append({"id": node.id, "name": node.name,
                        "status": node.status, "version": node.version})
    db.commit()
    audit(db, actor=admin.email, actor_type="user", action="node.update_all",
          target="*", detail={"count": len(flagged), "online_only": online})
    return {"count": len(flagged), "nodes": flagged}


@router.post("/{node_id}/update", response_model=NodeOut)
def request_update(node_id: str, db: Session = Depends(get_db),
                   admin: Principal = Depends(require_admin)):
    """Flag a node to self-update (git pull + restart) on its next heartbeat."""
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")
    now = int(utcnow().timestamp())
    upd = dict((node.meta or {}).get("update") or {})
    upd.update({"state": "requested", "requested_at": now, "from_version": node.version})
    node.meta = {**(node.meta or {}), "update_requested": True, "update": upd}
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


@router.get("/{node_id}/detail")
def node_detail(node_id: str, db: Session = Depends(get_db),
                _: Principal = Depends(require_admin),
                flow_limit: int = Query(50, le=500)):
    """Node drill-down: health, live peer links, attached endpoints (ingress),
    recent traffic through the node, and 24h traffic totals."""
    node = db.get(Node, node_id)
    if not node:
        raise HTTPException(404, "node not found")

    names = {n.id: n.name for n in db.scalars(select(Node))}
    link_rows = db.scalars(
        select(FabricLink).where(or_(FabricLink.node_a == node_id, FabricLink.node_b == node_id))
    )
    links = []
    for l in link_rows:
        peer_id = l.node_b if l.node_a == node_id else l.node_a
        links.append({
            "peer_id": peer_id, "peer_name": names.get(peer_id, peer_id),
            "status": l.status, "latency_ms": l.latency_ms, "loss_pct": l.loss_pct,
            "tx_bytes": l.tx_bytes, "rx_bytes": l.rx_bytes,
            "last_handshake": l.last_handshake,
        })

    endpoints = []
    if NodeRole.ingress.value in (node.roles or []):
        for e in db.scalars(select(Endpoint).where(Endpoint.ingress_node_id == node_id)
                            .order_by(Endpoint.name)):
            conn = (e.meta or {}).get("conn") or {}
            endpoints.append({
                "id": e.id, "name": e.name, "status": e.status, "address": e.address,
                "user": e.user_email or e.user_uid, "last_seen": e.last_seen,
                "connected": bool(conn.get("connected")),
                "rx_bytes": conn.get("rx_bytes", 0), "tx_bytes": conn.get("tx_bytes", 0),
            })

    flows = db.scalars(
        select(FlowRecord).where(or_(FlowRecord.node_id == node_id,
                                     FlowRecord.egress_node_id == node_id))
        .order_by(desc(FlowRecord.ts)).limit(flow_limit)
    )
    flow_rows = [
        {"id": r.id, "ts": r.ts, "endpoint_id": r.endpoint_id, "src_ip": r.src_ip,
         "dst_ip": r.dst_ip, "dst_port": r.dst_port, "domain": r.domain, "sni": r.sni,
         "category": r.category, "country": r.country, "verdict": r.verdict,
         "egress_ip": r.egress_ip, "tx_bytes": r.tx_bytes, "rx_bytes": r.rx_bytes}
        for r in flows
    ]

    since = utcnow() - dt.timedelta(hours=24)
    tx = db.scalar(select(func.coalesce(func.sum(FlowRecord.tx_bytes), 0))
                   .where(or_(FlowRecord.node_id == node_id, FlowRecord.egress_node_id == node_id),
                          FlowRecord.ts >= since)) or 0
    rx = db.scalar(select(func.coalesce(func.sum(FlowRecord.rx_bytes), 0))
                   .where(or_(FlowRecord.node_id == node_id, FlowRecord.egress_node_id == node_id),
                          FlowRecord.ts >= since)) or 0
    flows_24h = db.scalar(select(func.count()).select_from(FlowRecord)
                          .where(or_(FlowRecord.node_id == node_id, FlowRecord.egress_node_id == node_id),
                                 FlowRecord.ts >= since)) or 0

    return {
        "node": {
            "id": node.id, "name": node.name, "roles": node.roles or [],
            "region": node.region, "status": node.status, "fabric_addr": node.fabric_addr,
            "public_endpoint": node.public_endpoint, "hostname": node.hostname,
            "version": node.version, "target_version": node.target_version,
            "last_seen": node.last_seen, "health": node.health or {},
            "endpoint_pool_cidr": node.endpoint_pool_cidr,
            "egress_ip_pool": node.egress_ip_pool or [],
            "private_routes": node.private_routes or [],
        },
        "links": links,
        "endpoints": endpoints,
        "flows": flow_rows,
        "totals": {"tx_bytes": int(tx), "rx_bytes": int(rx), "flows_24h": int(flows_24h)},
    }

