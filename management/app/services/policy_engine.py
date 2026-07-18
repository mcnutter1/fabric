"""Policy engine — evaluates identity- and device-aware decisions.

A decision context is matched against enabled policies (by priority) and their
ordered rules (first match wins). The engine returns a `Decision` with an action
and parameters. It also compiles compact per-node "policy hints" the data plane
uses for inline DNS/TLS decisions and egress steering.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Policy, PolicyRule
from ..models.enums import PolicyAction


@dataclass
class PolicyContext:
    # identity
    user_uid: str = ""
    username: str = ""
    email: str = ""
    roles: list[str] = field(default_factory=list)
    # source / device
    endpoint_id: str = ""
    src_ip: str = ""
    node_role: str = ""
    # destination
    dst_ip: str = ""
    domain: str = ""
    category: str = ""
    port: int = 0
    protocol: str = ""
    # context
    country: str = ""
    asn: int = 0
    weekday: int = -1     # 0=Mon
    minute_of_day: int = -1


@dataclass
class Decision:
    action: str
    params: dict = field(default_factory=dict)
    policy_id: str = ""
    rule_id: int = 0
    rule_name: str = ""
    reason: str = ""

    @property
    def allowed(self) -> bool:
        return self.action not in (PolicyAction.deny.value, PolicyAction.block_page.value)


class PolicyEngine:
    def __init__(self, db: Session):
        self.db = db

    def _policies(self) -> list[Policy]:
        return list(
            self.db.scalars(
                select(Policy).where(Policy.enabled == True).order_by(Policy.priority)  # noqa: E712
            )
        )

    def evaluate(self, ctx: PolicyContext) -> Decision:
        for policy in self._policies():
            for rule in policy.rules:
                if not rule.enabled:
                    continue
                if self._rule_matches(rule, ctx):
                    return Decision(
                        action=rule.action,
                        params=rule.action_params or {},
                        policy_id=policy.id,
                        rule_id=rule.id,
                        rule_name=rule.name,
                        reason=f"matched rule '{rule.name}' in policy '{policy.name}'",
                    )
            # No rule matched — apply this policy's default if it is the first (highest-priority) policy.
            # We only short-circuit on the top policy's default to allow layered policies.
        # Global default: allow (explicit default lives on the top policy).
        policies = self._policies()
        if policies:
            top = policies[0]
            return Decision(action=top.default_action, params={}, policy_id=top.id,
                            reason=f"default action of policy '{top.name}'")
        return Decision(action=PolicyAction.allow.value, reason="no policies defined")

    # ------------------------------------------------------------------ matching
    def _rule_matches(self, rule: PolicyRule, ctx: PolicyContext) -> bool:
        checks = [
            self._match_roles(rule.match_roles, ctx.roles),
            self._match_users(rule.match_users, ctx),
            self._match_cidrs(rule.match_src_cidrs, ctx.src_ip),
            self._match_list(rule.match_endpoints, ctx.endpoint_id),
            self._match_list(rule.match_node_roles, ctx.node_role),
            self._match_cidrs(rule.match_dst_cidrs, ctx.dst_ip),
            self._match_domains(rule.match_domains, ctx.domain),
            self._match_list(rule.match_categories, ctx.category),
            self._match_ports(rule.match_ports, ctx.port),
            self._match_list(rule.match_protocols, ctx.protocol),
            self._match_list(rule.match_countries, ctx.country),
            self._match_asns(rule.match_asns, ctx.asn),
            self._match_time(rule.match_time, ctx),
        ]
        return all(checks)

    @staticmethod
    def _match_roles(required: list, roles: list) -> bool:
        if not required:
            return True
        return any(r in roles for r in required)

    @staticmethod
    def _match_users(required: list, ctx: PolicyContext) -> bool:
        if not required:
            return True
        return any(u in (ctx.user_uid, ctx.username, ctx.email) for u in required)

    @staticmethod
    def _match_list(required: list, value) -> bool:
        if not required:
            return True
        return value in required

    @staticmethod
    def _match_cidrs(cidrs: list, ip: str) -> bool:
        if not cidrs:
            return True
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for c in cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    @staticmethod
    def _match_domains(patterns: list, domain: str) -> bool:
        if not patterns:
            return True
        if not domain:
            return False
        domain = domain.lower().rstrip(".")
        for p in patterns:
            p = p.lower().lstrip("*.")
            if domain == p or domain.endswith("." + p) or fnmatch.fnmatch(domain, p):
                return True
        return False

    @staticmethod
    def _match_ports(ports: list, port: int) -> bool:
        if not ports:
            return True
        for p in ports:
            if isinstance(p, str) and "-" in p:
                lo, hi = p.split("-", 1)
                if int(lo) <= port <= int(hi):
                    return True
            elif int(p) == port:
                return True
        return False

    @staticmethod
    def _match_asns(asns: list, asn: int) -> bool:
        if not asns:
            return True
        return asn in [int(a) for a in asns]

    @staticmethod
    def _match_time(spec: dict, ctx: PolicyContext) -> bool:
        if not spec:
            return True
        days = spec.get("days")
        if days and ctx.weekday not in days:
            return False
        start = spec.get("start")  # minutes since midnight
        end = spec.get("end")
        if start is not None and end is not None and ctx.minute_of_day >= 0:
            if not (start <= ctx.minute_of_day <= end):
                return False
        return True

    # ------------------------------------------------------------------ compilation
    def compile_hints(self) -> dict:
        """Compile a compact policy bundle for the data plane (pushed to nodes)."""
        bundle = {"policies": []}
        for policy in self._policies():
            bundle["policies"].append({
                "id": policy.id,
                "name": policy.name,
                "priority": policy.priority,
                "default_action": policy.default_action,
                "rules": [
                    {
                        "id": r.id,
                        "name": r.name,
                        "match": {
                            "roles": r.match_roles, "users": r.match_users,
                            "src_cidrs": r.match_src_cidrs, "endpoints": r.match_endpoints,
                            "node_roles": r.match_node_roles, "dst_cidrs": r.match_dst_cidrs,
                            "domains": r.match_domains, "categories": r.match_categories,
                            "ports": r.match_ports, "protocols": r.match_protocols,
                            "countries": r.match_countries, "asns": r.match_asns,
                            "time": r.match_time,
                        },
                        "action": r.action,
                        "params": r.action_params,
                    }
                    for r in policy.rules if r.enabled
                ],
            })
        return bundle
