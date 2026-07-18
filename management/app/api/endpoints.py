"""Endpoint (client/device) management and config provisioning."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin
from ..database import get_db
from ..models import Endpoint, Node, FlowRecord, DnsLog, AuditLog
from ..models.enums import NodeRole, EndpointStatus, EndpointProtocol
from ..schemas import EndpointCreate, EndpointOut, EndpointBundleOut
from ..services import config_gen
from ..services.pki import PKIService
from ..services.wireguard import generate_keypair, generate_preshared_key, AddressAllocator
from ..util import new_id, audit

router = APIRouter(prefix="/endpoints", tags=["endpoints"])


def _endpoint_dict(ep: Endpoint) -> dict:
    """Public serialisation including live connection detail (from meta.conn)."""
    conn = (ep.meta or {}).get("conn") or {}
    return {
        "id": ep.id,
        "name": ep.name,
        "user_uid": ep.user_uid,
        "user_email": ep.user_email,
        "user_name": ep.user_name,
        "protocol": ep.protocol,
        "os": ep.os,
        "status": ep.status,
        "ingress_node_id": ep.ingress_node_id,
        "address": ep.address,
        "wg_public_key": ep.wg_public_key,
        "inspect_tls": ep.inspect_tls,
        "tags": ep.tags or [],
        "last_seen": ep.last_seen,
        "created_at": ep.created_at,
        "conn": {
            "connected": bool(conn.get("connected")),
            "last_handshake": conn.get("last_handshake", 0),
            "handshake_age": conn.get("handshake_age"),
            "rx_bytes": conn.get("rx_bytes", 0),
            "tx_bytes": conn.get("tx_bytes", 0),
            "remote_ip": conn.get("remote_ip", ""),
        },
    }



def _pick_ingress(db: Session, preferred: Optional[str]) -> Node:
    if preferred:
        node = db.get(Node, preferred)
        if not node:
            raise HTTPException(404, "ingress node not found")
        return node
    # JSON `contains` is unreliable on SQLite, so filter role membership in python.
    for n in db.scalars(select(Node)):
        if NodeRole.ingress.value in (n.roles or []):
            return n
    raise HTTPException(400, "no ingress node available")


def _allocate_endpoint_addr(db: Session, ingress: Node) -> str:
    cidr = ingress.endpoint_pool_cidr
    if not cidr:
        raise HTTPException(400, "ingress node has no endpoint pool CIDR")
    used = {e.address for e in db.scalars(select(Endpoint).where(Endpoint.ingress_node_id == ingress.id)) if e.address}
    used.add(str(AddressAllocator(cidr).first_host()))  # reserve .1 for the gateway/DNS
    return AddressAllocator(cidr).allocate(used)


@router.get("")
def list_endpoints(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    return [_endpoint_dict(e) for e in db.scalars(select(Endpoint).order_by(Endpoint.name))]


@router.post("", response_model=EndpointOut, status_code=201)
def create_endpoint(body: EndpointCreate, db: Session = Depends(get_db),
                    admin: Principal = Depends(require_admin)):
    ingress = _pick_ingress(db, body.ingress_node_id)
    keypair = generate_keypair()
    endpoint = Endpoint(
        id=new_id("ep_"),
        name=body.name,
        user_uid=body.user_uid,
        user_email=body.user_email,
        user_name=body.user_name,
        protocol=body.protocol,
        os=body.os,
        status=EndpointStatus.provisioned.value,
        ingress_node_id=ingress.id,
        address=_allocate_endpoint_addr(db, ingress),
        wg_public_key=keypair.public_key,
        preshared_key=generate_preshared_key(),
        inspect_tls=body.inspect_tls,
        tags=body.tags,
        # Stash the private key transiently so the first config fetch can return it,
        # then it is wiped. It is never returned again.
        meta={"_pending_private_key": keypair.private_key},
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    audit(db, actor=admin.email, actor_type="user", action="endpoint.create", target=endpoint.id)
    return endpoint


@router.get("/{endpoint_id}", response_model=EndpointOut)
def get_endpoint(endpoint_id: str, db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "endpoint not found")
    return ep


@router.get("/{endpoint_id}/detail")
def endpoint_detail(endpoint_id: str, db: Session = Depends(get_db),
                    _: Principal = Depends(require_admin),
                    flow_limit: int = Query(50, le=500)):
    """Full endpoint drill-down: identity, connection state, the ingress it
    terminates on, and its recent traffic / DNS / management activity."""
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "endpoint not found")

    ingress = db.get(Node, ep.ingress_node_id) if ep.ingress_node_id else None
    ingress_out = None
    if ingress:
        ingress_out = {
            "id": ingress.id, "name": ingress.name, "roles": ingress.roles or [],
            "region": ingress.region, "status": ingress.status,
            "public_endpoint": ingress.public_endpoint, "hostname": ingress.hostname,
        }

    flows = db.scalars(
        select(FlowRecord).where(FlowRecord.endpoint_id == endpoint_id)
        .order_by(desc(FlowRecord.ts)).limit(flow_limit)
    )
    flow_rows = [
        {"id": r.id, "ts": r.ts, "dst_ip": r.dst_ip, "dst_port": r.dst_port,
         "domain": r.domain, "sni": r.sni, "category": r.category, "app": r.app,
         "country": r.country, "isp": r.isp, "verdict": r.verdict,
         "egress_ip": r.egress_ip, "tx_bytes": r.tx_bytes, "rx_bytes": r.rx_bytes}
        for r in flows
    ]

    dns = db.scalars(
        select(DnsLog).where(DnsLog.endpoint_id == endpoint_id)
        .order_by(desc(DnsLog.ts)).limit(flow_limit)
    )
    dns_rows = [
        {"id": r.id, "ts": r.ts, "qname": r.qname, "qtype": r.qtype,
         "answer": r.answer, "category": r.category, "action": r.action}
        for r in dns
    ]

    activity = db.scalars(
        select(AuditLog).where(AuditLog.target == endpoint_id)
        .order_by(desc(AuditLog.ts)).limit(50)
    )
    activity_rows = [
        {"ts": a.ts, "actor": a.actor, "actor_type": a.actor_type,
         "action": a.action, "detail": a.detail or {}}
        for a in activity
    ]

    # 24h traffic totals for this endpoint.
    from sqlalchemy import func
    tx = db.scalar(select(func.coalesce(func.sum(FlowRecord.tx_bytes), 0))
                   .where(FlowRecord.endpoint_id == endpoint_id)) or 0
    rx = db.scalar(select(func.coalesce(func.sum(FlowRecord.rx_bytes), 0))
                   .where(FlowRecord.endpoint_id == endpoint_id)) or 0
    flow_count = db.scalar(select(func.count()).select_from(FlowRecord)
                           .where(FlowRecord.endpoint_id == endpoint_id)) or 0

    return {
        "endpoint": _endpoint_dict(ep),
        "ingress": ingress_out,
        "totals": {"tx_bytes": int(tx), "rx_bytes": int(rx), "flows": int(flow_count)},
        "flows": flow_rows,
        "dns": dns_rows,
        "activity": activity_rows,
    }



@router.delete("/{endpoint_id}", status_code=204)
def revoke_endpoint(endpoint_id: str, db: Session = Depends(get_db), admin: Principal = Depends(require_admin)):
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "endpoint not found")
    ep.status = EndpointStatus.revoked.value
    db.commit()
    audit(db, actor=admin.email, actor_type="user", action="endpoint.revoke", target=endpoint_id)


@router.get("/{endpoint_id}/config", response_model=EndpointBundleOut)
def endpoint_config(endpoint_id: str, db: Session = Depends(get_db), admin: Principal = Depends(require_admin)):
    """Return the downloadable config bundle. The private key is delivered here once."""
    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "endpoint not found")
    bundle, ep = build_endpoint_bundle(db, ep)
    audit(db, actor=admin.email, actor_type="user", action="endpoint.config", target=endpoint_id)
    return EndpointBundleOut(
        endpoint=EndpointOut.model_validate(ep),
        protocol=bundle.protocol, os=bundle.os, filename=bundle.filename,
        config_text=bundle.config_text, qr_png_b64=bundle.qr_png_b64,
        trusted_root_pem=bundle.trusted_root_pem, install_steps=bundle.install_steps,
    )


def build_endpoint_bundle(db: Session, ep: Endpoint):
    """Shared bundle builder: delivers the private key once, rotating the
    keypair on subsequent fetches so a re-download always yields a usable conf.
    Returns (bundle, endpoint)."""
    ingress = db.get(Node, ep.ingress_node_id) if ep.ingress_node_id else None
    if not ingress:
        raise HTTPException(400, "endpoint has no ingress node")
    meta = dict(ep.meta or {})
    private_key = meta.pop("_pending_private_key", "")
    if not private_key and ep.protocol == EndpointProtocol.wireguard.value:
        keypair = generate_keypair()
        ep.wg_public_key = keypair.public_key
        private_key = keypair.private_key
    ep.meta = meta  # wipe transient key
    db.commit()
    pki = PKIService(db)
    bundle = config_gen.build_bundle(ep, ingress, private_key, pki.trusted_root_bundle())
    return bundle, ep


@router.post("/{endpoint_id}/provision-link")
def create_provision_link(endpoint_id: str, ttl_hours: int = 24, db: Session = Depends(get_db),
                          admin: Principal = Depends(require_admin)):
    """Mint a short-lived, shareable link a user can open on their phone to
    download the config / scan the QR without operator credentials."""
    import datetime as dt
    from ..config import settings
    from ..models import ProvisioningToken
    from ..util import gen_token

    ep = db.get(Endpoint, endpoint_id)
    if not ep:
        raise HTTPException(404, "endpoint not found")
    # Retire any older active tokens for this endpoint.
    for t in db.scalars(select(ProvisioningToken).where(
            ProvisioningToken.endpoint_id == endpoint_id, ProvisioningToken.revoked == False)):  # noqa: E712
        t.revoked = True
    ttl = max(1, min(ttl_hours, 24 * 30))
    token = gen_token("prov_")
    pt = ProvisioningToken(
        token=token, endpoint_id=endpoint_id,
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=ttl),
    )
    db.add(pt)
    db.commit()
    audit(db, actor=admin.email, actor_type="user", action="endpoint.provision_link", target=endpoint_id)
    base = settings.public_url.rstrip("/")
    return {"url": f"{base}/p/{token}", "token": token, "expires_at": pt.expires_at}
