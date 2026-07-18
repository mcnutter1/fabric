"""Telemetry models: flow records, DNS logs, and audit trail."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import String, Integer, DateTime, JSON, BigInteger, Text, Index
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class FlowRecord(Base):
    """A single classified traffic flow observed by a node."""
    __tablename__ = "flow_records"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    node_id: Mapped[str] = mapped_column(String(40), index=True)
    endpoint_id: Mapped[str] = mapped_column(String(40), default="", index=True)

    user_uid: Mapped[str] = mapped_column(String(64), default="")
    src_ip: Mapped[str] = mapped_column(String(64), default="")
    dst_ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    dst_port: Mapped[int] = mapped_column(Integer, default=0)
    protocol: Mapped[str] = mapped_column(String(16), default="")
    sni: Mapped[str] = mapped_column(String(255), default="", index=True)

    # classification / enrichment
    domain: Mapped[str] = mapped_column(String(255), default="")
    category: Mapped[str] = mapped_column(String(64), default="")
    app: Mapped[str] = mapped_column(String(64), default="")
    country: Mapped[str] = mapped_column(String(4), default="")
    asn: Mapped[int] = mapped_column(Integer, default=0)
    isp: Mapped[str] = mapped_column(String(120), default="")
    ja3: Mapped[str] = mapped_column(String(64), default="")

    # decision
    verdict: Mapped[str] = mapped_column(String(20), default="allowed")
    egress_node_id: Mapped[str] = mapped_column(String(40), default="")
    egress_ip: Mapped[str] = mapped_column(String(64), default="")
    risk: Mapped[int] = mapped_column(Integer, default=0)

    tx_bytes: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), default=0)
    rx_bytes: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    # deep heuristics (http host/path, content-type, tls version, ja3s, payload
    # samples, parsed fields, etc.) — kept in JSON so the schema can evolve.
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    # geo hint for the live map (lat/lon of dst)
    geo: Mapped[dict] = mapped_column(JSON, default=dict)


class DnsLog(Base):
    __tablename__ = "dns_logs"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    node_id: Mapped[str] = mapped_column(String(40), index=True)
    endpoint_id: Mapped[str] = mapped_column(String(40), default="", index=True)
    user_uid: Mapped[str] = mapped_column(String(64), default="")
    client_ip: Mapped[str] = mapped_column(String(64), default="")

    qname: Mapped[str] = mapped_column(String(255), index=True)
    qtype: Mapped[str] = mapped_column(String(12), default="A")
    answer: Mapped[str] = mapped_column(String(512), default="")
    category: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(16), default="resolve")
    latency_ms: Mapped[float] = mapped_column(Integer, default=0)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"),
                                    primary_key=True, autoincrement=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(200), default="")   # user email/uid or node id
    actor_type: Mapped[str] = mapped_column(String(20), default="user")
    action: Mapped[str] = mapped_column(String(80), default="")
    target: Mapped[str] = mapped_column(String(200), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")


Index("ix_flow_ts_node", FlowRecord.ts, FlowRecord.node_id)
