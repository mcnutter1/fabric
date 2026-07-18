"""Node, pairing, and fabric-link models (the data-plane inventory)."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Float, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .enums import NodeStatus, LinkStatus


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    # A node can hold multiple roles, stored as a JSON list of NodeRole values.
    roles: Mapped[list] = mapped_column(JSON, default=list)
    region: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(20), default=NodeStatus.pending.value)

    # Fabric identity
    fabric_addr: Mapped[str] = mapped_column(String(64), default="")  # overlay IP
    wg_public_key: Mapped[str] = mapped_column(String(64), default="")
    wg_listen_port: Mapped[int] = mapped_column(Integer, default=51820)
    public_endpoint: Mapped[str] = mapped_column(String(255), default="")  # host:port reachable by peers

    # Role-specific config
    endpoint_pool_cidr: Mapped[str] = mapped_column(String(64), default="")   # ingress: pool for clients
    egress_ip_pool: Mapped[list] = mapped_column(JSON, default=list)          # egress: selectable exit IPs
    private_routes: Mapped[list] = mapped_column(JSON, default=list)          # connector: advertised CIDRs

    # Ops
    version: Mapped[str] = mapped_column(String(40), default="")
    target_version: Mapped[str] = mapped_column(String(40), default="")
    last_seen: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    health: Mapped[dict] = mapped_column(JSON, default=dict)                  # cpu, mem, iface stats
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="ingress_node")  # noqa: F821


class PairingCode(Base):
    __tablename__ = "pairing_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"))
    issued_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # bootstrap secret the node uses to obtain its long-lived API token
    enrollment_secret: Mapped[str] = mapped_column(String(128), default="")

    @property
    def is_valid(self) -> bool:
        now = _utcnow()
        exp = self.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        return self.used_at is None and now < exp


class NodeToken(Base):
    """Long-lived bearer token a paired node uses to authenticate to the API."""
    __tablename__ = "node_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_id: Mapped[str] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), index=True)  # sha256 of the token
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class FabricLink(Base):
    """A WireGuard peering between two nodes, with live link stats."""
    __tablename__ = "fabric_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    node_a: Mapped[str] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    node_b: Mapped[str] = mapped_column(ForeignKey("nodes.id", ondelete="CASCADE"), index=True)
    status: Mapped[str] = mapped_column(String(20), default=LinkStatus.down.value)
    latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    loss_pct: Mapped[float] = mapped_column(Float, default=0.0)
    tx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    rx_bytes: Mapped[int] = mapped_column(Integer, default=0)
    last_handshake: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
