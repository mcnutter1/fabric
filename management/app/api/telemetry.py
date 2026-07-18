"""Telemetry routes — node ingestion (flows/DNS) and operator queries/analytics."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin, require_node
from ..database import get_db
from ..models import FlowRecord, DnsLog, Node, Endpoint
from ..models.enums import EndpointStatus
from ..schemas import FlowIngest, DnsIngest, EndpointStatIngest
from ..realtime import hub
from ..util import utcnow

router = APIRouter(tags=["telemetry"])

# A handshake newer than this many seconds means the endpoint is actively connected.
_ACTIVE_HANDSHAKE_SEC = 180

# The same logical connection is observed independently by the ingress node and
# the egress/connector node (each reads its own conntrack table). Two reports of
# the same (endpoint, dst, port, proto) tuple within this window are treated as
# one flow so the record carries BOTH the ingress and egress hops.
_FLOW_CORRELATE_SEC = 120


def _reporter_role(node: "Node", ep: "Endpoint | None") -> str:
    """Classify how the reporting node sits on this flow: 'ingress' (the client's
    entry node / inspection point) or 'egress' (the exit node — egress or private
    connector). Ownership of the endpoint's pool wins over generic roles."""
    roles = node.roles or []
    if ep is not None and ep.ingress_node_id and ep.ingress_node_id == node.id:
        return "ingress"
    if any(r in ("egress", "private_connector") for r in roles):
        return "egress"
    return "ingress"


def _merge_flow(rec: "FlowRecord", node: "Node", role: str, data: dict,
                ep: "Endpoint | None", now) -> None:
    """Fold a second observation of the same flow into an existing record."""
    if role == "ingress":
        rec.node_id = node.id
        # The ingress does inspection/classification — prefer its enrichment.
        for fld in ("sni", "domain", "category", "app", "ja3", "verdict", "risk", "user_uid"):
            val = data.get(fld)
            if val:
                setattr(rec, fld, val)
    else:  # egress / connector
        rec.egress_node_id = node.id
        if data.get("egress_ip"):
            rec.egress_ip = data["egress_ip"]
        # If the ingress hasn't reported yet, attribute it from the endpoint.
        if ep is not None and ep.ingress_node_id and (not rec.node_id or rec.node_id == node.id):
            rec.node_id = ep.ingress_node_id
        # The exit node carries the geo/ASN enrichment for the real destination.
        for fld in ("country", "asn", "isp", "geo"):
            val = data.get(fld)
            if val:
                setattr(rec, fld, val)
    # Each node counts bytes on its own leg; take the larger to avoid double count.
    rec.tx_bytes = max(rec.tx_bytes or 0, data.get("tx_bytes", 0) or 0)
    rec.rx_bytes = max(rec.rx_bytes or 0, data.get("rx_bytes", 0) or 0)
    if data.get("duration_ms"):
        rec.duration_ms = max(rec.duration_ms or 0, data["duration_ms"])
    if data.get("meta"):
        merged = dict(rec.meta or {})
        merged.update(data["meta"])
        rec.meta = merged
    rec.ts = now


def _new_flow(node: "Node", role: str, data: dict, ep: "Endpoint | None") -> "FlowRecord":
    """Create a record, pre-filling both hop ids from the reporter's role so the
    path shows ingress -> egress even when only one node has reported so far."""
    payload = dict(data)
    egress_node_id = payload.pop("egress_node_id", "")
    if role == "ingress":
        node_id = node.id
    else:
        node_id = ep.ingress_node_id if (ep and ep.ingress_node_id) else node.id
        egress_node_id = node.id
    return FlowRecord(node_id=node_id, egress_node_id=egress_node_id, **payload)


def _flow_public(rec: "FlowRecord") -> dict:
    return {
        "id": rec.id, "ts": rec.ts, "node_id": rec.node_id,
        "egress_node_id": rec.egress_node_id, "endpoint_id": rec.endpoint_id,
        "user_uid": rec.user_uid, "src_ip": rec.src_ip, "dst_ip": rec.dst_ip,
        "dst_port": rec.dst_port, "protocol": rec.protocol, "sni": rec.sni,
        "domain": rec.domain, "category": rec.category, "country": rec.country,
        "asn": rec.asn, "isp": rec.isp, "verdict": rec.verdict,
        "egress_ip": rec.egress_ip, "tx_bytes": rec.tx_bytes, "rx_bytes": rec.rx_bytes,
        "geo": rec.geo or {},
    }


# ------------------------------------------------------------------ ingestion (nodes)
@router.post("/node/flows")
async def ingest_flows(flows: list[FlowIngest], node: Node = Depends(require_node),
                       db: Session = Depends(get_db)):
    # Map endpoint overlay IPs -> endpoint so egress-observed flows (which only
    # carry a src_ip) get attributed to the client that generated them.
    ep_by_addr = {
        e.address: e for e in db.scalars(select(Endpoint).where(Endpoint.address != ""))
    }
    now = utcnow()
    window = now - dt.timedelta(seconds=_FLOW_CORRELATE_SEC)
    stored: list[dict] = []
    seen_eps: dict[str, Endpoint] = {}
    for f in flows:
        data = f.model_dump()
        ep = ep_by_addr.get(data.get("src_ip", "")) if data.get("src_ip") else None
        if ep is None and data.get("endpoint_id"):
            ep = db.get(Endpoint, data["endpoint_id"])
        if ep is not None:
            if not data.get("endpoint_id"):
                data["endpoint_id"] = ep.id
            if not data.get("user_uid"):
                data["user_uid"] = ep.user_uid or ep.user_email
            seen_eps[ep.id] = ep

        role = _reporter_role(node, ep)

        # Correlate with the peer node's observation of the same connection so a
        # single record spans ingress -> egress instead of one row per node.
        q = select(FlowRecord).where(
            FlowRecord.dst_ip == data.get("dst_ip", ""),
            FlowRecord.dst_port == data.get("dst_port", 0),
            FlowRecord.protocol == data.get("protocol", ""),
            FlowRecord.ts >= window,
        )
        if data.get("endpoint_id"):
            q = q.where(FlowRecord.endpoint_id == data["endpoint_id"])
        else:
            q = q.where(FlowRecord.src_ip == data.get("src_ip", ""))
        match = db.scalars(q.order_by(desc(FlowRecord.ts)).limit(1)).first()

        if match is not None:
            _merge_flow(match, node, role, data, ep, now)
            rec = match
        else:
            rec = _new_flow(node, role, data, ep)
            db.add(rec)
        stored.append(rec)
    # Active traffic is itself proof of life: keep last_seen fresh and promote
    # provisioned/idle endpoints to active even before the ingress agent reports
    # WireGuard handshake stats.
    for ep in seen_eps.values():
        ep.last_seen = now
        if ep.status in (EndpointStatus.provisioned.value, EndpointStatus.idle.value):
            ep.status = EndpointStatus.active.value
    db.commit()
    # Fan out to the live map (cap payload).
    for rec in stored[:50]:
        await hub.publish("flow", _flow_public(rec))
    return {"ok": True, "stored": len(stored)}


@router.post("/node/dns")
async def ingest_dns(logs: list[DnsIngest], node: Node = Depends(require_node),
                     db: Session = Depends(get_db)):
    for d in logs:
        db.add(DnsLog(node_id=node.id, **d.model_dump()))
    db.commit()
    for d in logs[:50]:
        await hub.publish("dns", {"node_id": node.id, **d.model_dump()})
    return {"ok": True, "stored": len(logs)}


@router.post("/node/endpoints")
async def ingest_endpoint_stats(stats: list[EndpointStatIngest],
                                node: Node = Depends(require_node),
                                db: Session = Depends(get_db)):
    """An ingress node reports live WireGuard connection stats for its client
    endpoints. Updates each endpoint's status, last_seen and connection detail."""
    now = utcnow()
    now_epoch = int(now.timestamp())
    updated = 0
    for s in stats:
        ep = None
        if s.endpoint_id:
            ep = db.get(Endpoint, s.endpoint_id)
        if not ep and s.wg_public_key:
            ep = db.scalar(select(Endpoint).where(Endpoint.wg_public_key == s.wg_public_key))
        if not ep:
            continue
        # A node may report an endpoint whose ingress binding is stale or unset
        # (e.g. it was just moved). Trust a matching public key and (re)bind it to
        # the reporting node rather than silently dropping the update.
        if ep.ingress_node_id and ep.ingress_node_id != node.id and not s.wg_public_key:
            continue
        if not ep.ingress_node_id:
            ep.ingress_node_id = node.id
        connected = bool(s.last_handshake) and (now_epoch - s.last_handshake) <= _ACTIVE_HANDSHAKE_SEC
        conn = {
            "connected": connected,
            "last_handshake": s.last_handshake or 0,
            "handshake_age": (now_epoch - s.last_handshake) if s.last_handshake else None,
            "rx_bytes": s.rx_bytes,
            "tx_bytes": s.tx_bytes,
            "remote_ip": s.remote_ip,
            "ingress_node_id": node.id,
            "updated": now_epoch,
        }
        ep.meta = {**(ep.meta or {}), "conn": conn}
        if s.last_handshake:
            ep.last_seen = dt.datetime.fromtimestamp(s.last_handshake, dt.timezone.utc)
        if ep.status != EndpointStatus.revoked.value:
            ep.status = EndpointStatus.active.value if connected else (
                EndpointStatus.idle.value if s.last_handshake else EndpointStatus.provisioned.value
            )
        updated += 1
        await hub.publish("endpoint.state", {
            "endpoint_id": ep.id, "name": ep.name, "status": ep.status,
            "node_id": node.id, "conn": conn,
        })
    db.commit()
    return {"ok": True, "updated": updated}



# ------------------------------------------------------------------ queries (operators)
@router.get("/flows")
def query_flows(db: Session = Depends(get_db), _: Principal = Depends(require_admin),
                limit: int = Query(200, le=2000), endpoint_id: str = "", verdict: str = ""):
    q = select(FlowRecord).order_by(desc(FlowRecord.ts))
    if endpoint_id:
        q = q.where(FlowRecord.endpoint_id == endpoint_id)
    if verdict:
        q = q.where(FlowRecord.verdict == verdict)
    rows = db.scalars(q.limit(limit))
    return [
        {
            "id": r.id, "ts": r.ts, "node_id": r.node_id, "endpoint_id": r.endpoint_id,
            "user_uid": r.user_uid, "src_ip": r.src_ip, "dst_ip": r.dst_ip, "dst_port": r.dst_port,
            "protocol": r.protocol, "sni": r.sni, "domain": r.domain, "category": r.category,
            "app": r.app, "country": r.country, "asn": r.asn, "isp": r.isp,
            "verdict": r.verdict, "egress_node_id": r.egress_node_id, "egress_ip": r.egress_ip,
            "risk": r.risk, "tx_bytes": r.tx_bytes, "rx_bytes": r.rx_bytes,
            "duration_ms": getattr(r, "duration_ms", 0) or 0, "meta": r.meta or {}, "geo": r.geo,
        }
        for r in rows
    ]


@router.get("/flows/{flow_id}")
def flow_detail(flow_id: int, db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    """Full record for one flow, plus the computed path it traversed:
    endpoint -> ingress node -> egress/connector node -> destination."""
    r = db.get(FlowRecord, flow_id)
    if not r:
        raise HTTPException(404, "flow not found")

    def _node_hop(node: "Node", kind: str, label: str) -> dict:
        return {
            "kind": kind, "label": label, "node_id": node.id, "name": node.name,
            "roles": node.roles or [], "region": node.region or "",
            "public_endpoint": node.public_endpoint or "",
            "status": getattr(node, "status", "") or "",
            "hostname": getattr(node, "hostname", "") or "",
        }

    hops: list[dict] = []
    ep = db.get(Endpoint, r.endpoint_id) if r.endpoint_id else None
    hops.append({
        "kind": "endpoint", "label": "Endpoint",
        "name": (ep.name if ep else (r.user_uid or r.src_ip or "client")),
        "detail": r.src_ip or (ep.address if ep else ""),
        "os": ep.os if ep else "", "user": (ep.user_email if ep else r.user_uid),
    })
    ingress = db.get(Node, r.node_id) if r.node_id else None
    if ingress:
        hops.append(_node_hop(ingress, "ingress", "Ingress / inspection"))
    egress = db.get(Node, r.egress_node_id) if r.egress_node_id else None
    if egress and (not ingress or egress.id != ingress.id):
        is_priv = "private_connector" in (egress.roles or [])
        hops.append(_node_hop(egress, "connector" if is_priv else "egress",
                              "Private connector" if is_priv else "Egress"))
    dest_kind = "private" if (r.meta or {}).get("destination_zone") == "private" else "internet"
    hops.append({
        "kind": dest_kind, "label": "Private network" if dest_kind == "private" else "Internet",
        "name": r.domain or r.sni or r.dst_ip, "detail": (r.dst_ip + ":" + str(r.dst_port)) if r.dst_ip else "",
        "country": r.country, "isp": r.isp, "asn": r.asn, "geo": r.geo,
    })

    return {
        "id": r.id, "ts": r.ts, "node_id": r.node_id, "endpoint_id": r.endpoint_id,
        "user_uid": r.user_uid, "src_ip": r.src_ip, "dst_ip": r.dst_ip, "dst_port": r.dst_port,
        "protocol": r.protocol, "sni": r.sni, "domain": r.domain, "category": r.category,
        "app": r.app, "country": r.country, "asn": r.asn, "isp": r.isp, "ja3": r.ja3,
        "verdict": r.verdict, "egress_node_id": r.egress_node_id, "egress_ip": r.egress_ip,
        "risk": r.risk, "tx_bytes": r.tx_bytes, "rx_bytes": r.rx_bytes,
        "duration_ms": getattr(r, "duration_ms", 0) or 0, "meta": r.meta or {}, "geo": r.geo,
        "path": hops,
    }


@router.get("/dns")
def query_dns(db: Session = Depends(get_db), _: Principal = Depends(require_admin),
              limit: int = Query(200, le=2000), action: str = ""):
    q = select(DnsLog).order_by(desc(DnsLog.ts))
    if action:
        q = q.where(DnsLog.action == action)
    rows = db.scalars(q.limit(limit))
    return [
        {"id": r.id, "ts": r.ts, "node_id": r.node_id, "endpoint_id": r.endpoint_id,
         "user_uid": r.user_uid, "client_ip": r.client_ip, "qname": r.qname, "qtype": r.qtype,
         "answer": r.answer, "category": r.category, "action": r.action,
         "latency_ms": r.latency_ms, "meta": (r.meta or {})}
        for r in rows
    ]


@router.get("/analytics/summary")
def analytics_summary(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=24)

    total_nodes = db.scalar(select(func.count()).select_from(Node)) or 0
    online_nodes = db.scalar(select(func.count()).select_from(Node).where(Node.status == "online")) or 0
    total_endpoints = db.scalar(select(func.count()).select_from(Endpoint)) or 0
    active_endpoints = db.scalar(
        select(func.count()).select_from(Endpoint).where(Endpoint.status == "active")
    ) or 0
    flows_24h = db.scalar(select(func.count()).select_from(FlowRecord).where(FlowRecord.ts >= since)) or 0
    blocked_24h = db.scalar(
        select(func.count()).select_from(FlowRecord).where(FlowRecord.ts >= since, FlowRecord.verdict == "denied")
    ) or 0
    dns_24h = db.scalar(select(func.count()).select_from(DnsLog).where(DnsLog.ts >= since)) or 0

    top_categories = db.execute(
        select(FlowRecord.category, func.count().label("n"))
        .where(FlowRecord.ts >= since, FlowRecord.category != "")
        .group_by(FlowRecord.category).order_by(desc("n")).limit(8)
    ).all()
    top_countries = db.execute(
        select(FlowRecord.country, func.count().label("n"))
        .where(FlowRecord.ts >= since, FlowRecord.country != "")
        .group_by(FlowRecord.country).order_by(desc("n")).limit(8)
    ).all()

    return {
        "nodes": {"total": total_nodes, "online": online_nodes},
        "endpoints": {"total": total_endpoints, "active": active_endpoints},
        "flows_24h": flows_24h,
        "blocked_24h": blocked_24h,
        "dns_24h": dns_24h,
        "top_categories": [{"category": c or "unknown", "count": n} for c, n in top_categories],
        "top_countries": [{"country": c, "count": n} for c, n in top_countries],
    }
