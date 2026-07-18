"""Node-facing routes — enrollment (pairing) and runtime (config/heartbeat/policy)."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import hash_token, require_node
from ..config import settings
from ..database import get_db
from ..models import Node, PairingCode, NodeToken, FabricLink
from ..models.enums import NodeStatus, LinkStatus, CertKind
from ..schemas import NodeEnrollRequest, NodeEnrollResponse, NodeHeartbeat
from ..services.fabric import FabricOrchestrator
from ..services.policy_engine import PolicyEngine
from ..services.pki import PKIService
from ..realtime import hub
from ..util import gen_token, utcnow, audit

router = APIRouter(prefix="/node", tags=["node"])


@router.post("/enroll", response_model=NodeEnrollResponse)
def enroll(body: NodeEnrollRequest, request: Request, db: Session = Depends(get_db)):
    pairing = db.scalar(select(PairingCode).where(PairingCode.code == body.code))
    if not pairing or not pairing.is_valid:
        raise HTTPException(401, "invalid or expired pairing code")
    node = db.get(Node, pairing.node_id)
    if not node:
        raise HTTPException(404, "node not found")

    # Bind the node's WireGuard identity + discovered endpoint.
    node.wg_public_key = body.wg_public_key
    node.version = body.version
    # The node's reachable address is discovered at registration time, not
    # entered by an operator during onboarding: prefer what the node advertises,
    # otherwise fall back to the source IP the manager observed for this request.
    if body.advertised_endpoint:
        node.public_endpoint = body.advertised_endpoint
    elif not node.public_endpoint and request.client:
        node.public_endpoint = f"{request.client.host}:{node.wg_listen_port}"
    node.status = NodeStatus.online.value
    node.last_seen = utcnow()

    # Issue a long-lived node token.
    token = gen_token("node_")
    db.add(NodeToken(node_id=node.id, token_hash=hash_token(token)))

    # Issue an infrastructure identity certificate for mTLS.
    pki = PKIService(db)
    sans = [node.name, node.fabric_addr]
    if node.public_endpoint:
        sans.append(node.public_endpoint.split(":")[0])
    issued = pki.issue_node_cert(node.id, cn=node.name, sans=[s for s in sans if s])

    pairing.used_at = utcnow()
    db.commit()

    FabricOrchestrator(db).compute_links()
    audit(db, actor=node.id, actor_type="node", action="node.enroll", target=node.id,
          ip=request.client.host if request.client else "")

    return NodeEnrollResponse(
        node_id=node.id,
        node_token=token,
        fabric_addr=node.fabric_addr,
        wg_listen_port=node.wg_listen_port,
        roles=node.roles or [],
        cert_pem=issued.cert_pem,
        key_pem=issued.key_pem or "",
        ca_chain_pem=issued.chain_pem,
        manager_ca_pem=pki.ca_pem(CertKind.root_ca) or "",
    )


@router.get("/config")
def get_config(node: Node = Depends(require_node), db: Session = Depends(get_db)):
    return FabricOrchestrator(db).compute_node_config(node)


@router.get("/policy")
def get_policy(node: Node = Depends(require_node), db: Session = Depends(get_db)):
    return PolicyEngine(db).compile_hints()


@router.get("/pki/mitm")
def get_mitm_ca(node: Node = Depends(require_node), db: Session = Depends(get_db)):
    """Egress nodes fetch the MITM CA (cert + key) to mint inspection leaves at line rate."""
    if "egress" not in (node.roles or []):
        raise HTTPException(403, "MITM CA only provisioned to egress nodes")
    from ..models import Certificate
    ca_rec = db.scalar(select(Certificate).where(Certificate.kind == CertKind.mitm_ca.value))
    if not ca_rec:
        raise HTTPException(404, "MITM CA not initialised")
    from ..services.pki import _decrypt_key
    key_pem = _decrypt_key(ca_rec.encrypted_key).decode() if ca_rec.encrypted_key else ""
    audit(db, actor=node.id, actor_type="node", action="pki.mitm_fetch", target=node.id)
    return {"ca_cert_pem": ca_rec.cert_pem, "ca_key_pem": key_pem}


@router.post("/heartbeat")
async def heartbeat(body: NodeHeartbeat, node: Node = Depends(require_node), db: Session = Depends(get_db)):
    node.last_seen = utcnow()
    node.health = body.health or {}
    if body.version:
        node.version = body.version
    if node.status in (NodeStatus.pairing.value, NodeStatus.pending.value, NodeStatus.offline.value):
        node.status = NodeStatus.online.value

    # Update pairwise link stats.
    for link_stat in body.links:
        peer_id = link_stat.get("peer_id")
        if not peer_id:
            continue
        a, b = sorted((node.id, peer_id))
        link = db.scalar(select(FabricLink).where(FabricLink.node_a == a, FabricLink.node_b == b))
        if not link:
            link = FabricLink(node_a=a, node_b=b)
            db.add(link)
        link.latency_ms = link_stat.get("latency_ms", link.latency_ms)
        link.loss_pct = link_stat.get("loss_pct", link.loss_pct)
        link.tx_bytes = link_stat.get("tx", link.tx_bytes)
        link.rx_bytes = link_stat.get("rx", link.rx_bytes)
        handshake = link_stat.get("last_handshake_ok", True)
        loss = link_stat.get("loss_pct", 0)
        link.status = (
            LinkStatus.up.value if handshake and loss < 20
            else LinkStatus.degraded.value if handshake
            else LinkStatus.down.value
        )
        if link.status == LinkStatus.up.value:
            link.last_handshake = utcnow()
    db.commit()

    await hub.publish("node.health", {"node_id": node.id, "status": node.status, "health": node.health})
    # Tell the node whether it should re-pull config (version drift).
    cfg = FabricOrchestrator(db).compute_node_config(node)
    # Fire a one-time self-update signal if an operator requested it.
    do_update = bool((node.meta or {}).get("update_requested"))
    if do_update:
        node.meta = {**(node.meta or {}), "update_requested": False}
        db.commit()
    return {"ok": True, "config_version": cfg["version"],
            "target_version": node.target_version or node.version, "update": do_update}
