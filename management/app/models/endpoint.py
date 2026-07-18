"""Endpoint (client/device) inventory model."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base
from .enums import EndpointStatus, EndpointProtocol, EndpointOS


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Endpoint(Base):
    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), index=True)

    # Identity binding (McNutt Cloud)
    user_uid: Mapped[str] = mapped_column(String(64), default="", index=True)
    user_email: Mapped[str] = mapped_column(String(200), default="")
    user_name: Mapped[str] = mapped_column(String(200), default="")

    # Access parameters
    protocol: Mapped[str] = mapped_column(String(24), default=EndpointProtocol.wireguard.value)
    os: Mapped[str] = mapped_column(String(24), default=EndpointOS.windows.value)
    status: Mapped[str] = mapped_column(String(20), default=EndpointStatus.provisioned.value)

    # Fabric attachment
    ingress_node_id: Mapped[Optional[str]] = mapped_column(ForeignKey("nodes.id", ondelete="SET NULL"), nullable=True)
    address: Mapped[str] = mapped_column(String(64), default="")  # assigned overlay IP
    wg_public_key: Mapped[str] = mapped_column(String(64), default="")
    # server keeps only the public key; the private key is delivered once in config and not stored
    preshared_key: Mapped[str] = mapped_column(String(64), default="")

    # Posture / inspection
    inspect_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    meta: Mapped[dict] = mapped_column(JSON, default=dict)

    last_seen: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    ingress_node: Mapped[Optional["Node"]] = relationship(back_populates="endpoints")  # noqa: F821


class ProvisioningToken(Base):
    """Short-lived, shareable token that lets an end user (e.g. a mobile
    device) fetch and install an endpoint's config without operator auth."""
    __tablename__ = "provisioning_tokens"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(String(40), index=True)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    expires_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    used_count: Mapped[int] = mapped_column(Integer, default=0)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)

    @property
    def is_valid(self) -> bool:
        now = dt.datetime.now(dt.timezone.utc)
        exp = self.expires_at
        if exp is not None and exp.tzinfo is None:
            exp = exp.replace(tzinfo=dt.timezone.utc)
        return (not self.revoked) and exp is not None and exp > now
