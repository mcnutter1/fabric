"""Policy and rule models for the policy engine."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import String, Integer, DateTime, ForeignKey, JSON, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    name: Mapped[str] = mapped_column(String(160), unique=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # lower number = higher precedence
    priority: Mapped[int] = mapped_column(Integer, default=100)
    # default action when no rule matches
    default_action: Mapped[str] = mapped_column(String(24), default="allow")

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    rules: Mapped[list["PolicyRule"]] = relationship(
        back_populates="policy", cascade="all, delete-orphan", order_by="PolicyRule.order"
    )


class PolicyRule(Base):
    __tablename__ = "policy_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    order: Mapped[int] = mapped_column(Integer, default=0)
    name: Mapped[str] = mapped_column(String(160), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    # --- Match criteria (all provided fields must match; empty = wildcard) ---
    # Identity
    match_roles: Mapped[list] = mapped_column(JSON, default=list)        # any-of roles
    match_users: Mapped[list] = mapped_column(JSON, default=list)        # uid / username / email
    # Source / device
    match_src_cidrs: Mapped[list] = mapped_column(JSON, default=list)
    match_endpoints: Mapped[list] = mapped_column(JSON, default=list)    # endpoint ids
    match_node_roles: Mapped[list] = mapped_column(JSON, default=list)
    # Destination
    match_dst_cidrs: Mapped[list] = mapped_column(JSON, default=list)
    match_domains: Mapped[list] = mapped_column(JSON, default=list)      # glob or suffix
    match_categories: Mapped[list] = mapped_column(JSON, default=list)   # URL categories
    match_ports: Mapped[list] = mapped_column(JSON, default=list)
    match_protocols: Mapped[list] = mapped_column(JSON, default=list)
    # Context
    match_countries: Mapped[list] = mapped_column(JSON, default=list)
    match_asns: Mapped[list] = mapped_column(JSON, default=list)
    match_time: Mapped[dict] = mapped_column(JSON, default=dict)         # {days, start, end}

    # --- Action ---
    action: Mapped[str] = mapped_column(String(24), default="allow")
    # action parameters, e.g. {"egress_node": "...", "region": "...", "url": "...",
    #                          "message": "...", "egress_ip": "..."}
    action_params: Mapped[dict] = mapped_column(JSON, default=dict)

    policy: Mapped["Policy"] = relationship(back_populates="rules")
