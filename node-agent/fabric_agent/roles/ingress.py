"""Ingress role — client tunnel termination + DNS filtering.

Terminates endpoint (client) tunnels and owns the endpoint address pool. Runs
the fabric DNS resolver that intercepts endpoint DNS, applies category/domain
policy, and logs every query.
"""
from __future__ import annotations

from .base import Role
from ..dns_filter import DNSResolver


class IngressRole(Role):
    name = "ingress"

    def __init__(self, agent):
        super().__init__(agent)
        self.dns = None

    def setup(self, config: dict) -> None:
        cfg = self.agent.cfg
        if self.dns is None:
            self.dns = DNSResolver(cfg.dns_listen, cfg.upstream_dns,
                                   self.classifier, self.telemetry.add_dns)
            started = self.dns.start()
            # Expose on the agent so apply_policy() can push updates.
            self.agent.dns = self.dns
            self.log.info("client ingress active (endpoint pool %s, dns=%s)",
                          config.get("routing", {}).get("endpoint_pool"),
                          "on" if started else "unavailable")
        if self.policy and self.dns:
            self.dns.set_policy(self.policy)

    def teardown(self) -> None:
        if self.dns:
            self.dns.stop()
