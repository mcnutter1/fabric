"""Agent-side policy evaluation over the compiled bundle from the manager.

Mirrors the management PolicyEngine semantics (first-match-wins across ordered
rules, per-policy default action) but operates on the flattened `hints` bundle
so the data plane can decide verdicts locally at line rate.
"""
from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FlowCtx:
    user_uid: str = ""
    roles: list = field(default_factory=list)
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    domain: str = ""
    category: str = ""
    country: str = ""
    asn: int = 0
    node_roles: list = field(default_factory=list)


@dataclass
class Verdict:
    action: str = "allow"
    rule_id: str = ""
    policy_id: str = ""
    params: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.action in ("allow", "inspect")


class PolicyBundle:
    def __init__(self, bundle: dict):
        # Sort policies by priority (lower first, matching manager).
        self.policies = sorted(bundle.get("policies", []), key=lambda p: p.get("priority", 100))

    def evaluate(self, ctx: FlowCtx) -> Verdict:
        for policy in self.policies:
            for rule in policy.get("rules", []):
                if self._matches(rule.get("match", {}), ctx):
                    return Verdict(rule.get("action", "allow"), rule.get("id", ""),
                                   policy.get("id", ""), rule.get("params", {}))
            # Policy default only applies if the policy targeted this ctx at all;
            # here we treat default as the fall-through of its highest priority.
        # Global fall-through: first policy's default, else allow.
        if self.policies:
            return Verdict(self.policies[0].get("default_action", "allow"), "", self.policies[0].get("id", ""))
        return Verdict("allow")

    # ------------------------------------------------------------ matching
    def _matches(self, m: dict, c: FlowCtx) -> bool:
        if m.get("roles") and not (set(m["roles"]) & set(c.roles)):
            return False
        if m.get("users") and c.user_uid not in m["users"]:
            return False
        if m.get("node_roles") and not (set(m["node_roles"]) & set(c.node_roles)):
            return False
        if m.get("categories") and c.category not in m["categories"]:
            return False
        if m.get("countries") and c.country not in m["countries"]:
            return False
        if m.get("asns") and c.asn not in m["asns"]:
            return False
        if m.get("ports") and c.dst_port not in m["ports"]:
            return False
        if m.get("protocols") and c.protocol not in m["protocols"]:
            return False
        if m.get("domains") and not self._domain_match(m["domains"], c.domain):
            return False
        if m.get("dst_cidrs") and not self._cidr_match(m["dst_cidrs"], c.dst_ip):
            return False
        if m.get("src_cidrs") and not self._cidr_match(m["src_cidrs"], c.src_ip):
            return False
        return True

    @staticmethod
    def _domain_match(patterns: list, domain: str) -> bool:
        d = (domain or "").lower()
        for p in patterns:
            p = p.lower()
            if d == p or d.endswith("." + p) or fnmatch.fnmatch(d, p):
                return True
        return False

    @staticmethod
    def _cidr_match(cidrs: list, ip: str) -> bool:
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
