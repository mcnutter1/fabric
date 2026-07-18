"""Telemetry routes — node ingestion (flows/DNS) and operator queries/analytics."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy import select, func, desc
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin, require_node
from ..database import get_db
from ..models import FlowRecord, DnsLog, Node, Endpoint
from ..schemas import FlowIngest, DnsIngest
from ..realtime import hub

router = APIRouter(tags=["telemetry"])


# ------------------------------------------------------------------ ingestion (nodes)
@router.post("/node/flows")
async def ingest_flows(flows: list[FlowIngest], node: Node = Depends(require_node),
                       db: Session = Depends(get_db)):
    stored = []
    for f in flows:
        rec = FlowRecord(node_id=node.id, **f.model_dump())
        db.add(rec)
        stored.append(f.model_dump())
    db.commit()
    # Fan out to the live map (cap payload).
    for f in stored[:50]:
        await hub.publish("flow", {"node_id": node.id, **f})
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
