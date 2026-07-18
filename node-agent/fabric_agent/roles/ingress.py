"""Ingress role — client tunnel termination + DNS filtering.

Terminates endpoint (client) tunnels and owns the endpoint address pool. Runs
the fabric DNS resolver that intercepts endpoint DNS, applies category/domain
policy, and logs every query. Also reports per-endpoint WireGuard connection
stats (handshake age, transfer counters, remote IP) back to the manager so the
console can show live endpoint status and activity.
"""
from __future__ import annotations

import time

from .base import Role
from ..dns_filter import DNSResolver


class IngressRole(Role):
    name = "ingress"

    def __init__(self, agent):
        super().__init__(agent)
        self.dns = None
        self._ep_by_pub: dict = {}      # wg public_key -> endpoint identity
        self._last_report = 0.0
        self._report_interval = 15      # seconds between endpoint stat reports

    def setup(self, config: dict) -> None:
        cfg = self.agent.cfg
        # Refresh the endpoint pubkey -> id map on every config apply.
        self._ep_by_pub = {
            e.get("public_key"): e
            for e in (config.get("endpoints") or [])
            if e.get("public_key")
        }
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

    def tick(self) -> None:
        now = time.time()
        if now - self._last_report < self._report_interval:
            return
        self._last_report = now
        self._report_endpoints()

    def _report_endpoints(self) -> None:
        if not self._ep_by_pub or not self.manager:
            return
        try:
            stats = self.agent.dp.wg_link_stats()
        except Exception as e:  # noqa: BLE001
            self.log.debug("wg stats unavailable: %s", e)
            return
        report = []
        for pub, ident in self._ep_by_pub.items():
            s = stats.get(pub)
            if not s:
                # Peer configured but no handshake yet — still report so the
                # manager can show "provisioned, not connected".
                report.append({
                    "endpoint_id": ident.get("endpoint_id", ""),
                    "wg_public_key": pub,
                    "last_handshake": 0, "rx_bytes": 0, "tx_bytes": 0,
                    "remote_ip": "",
                })
                continue
            report.append({
                "endpoint_id": ident.get("endpoint_id", ""),
                "wg_public_key": pub,
                "last_handshake": s.get("last_handshake", 0),
                "rx_bytes": s.get("rx", 0),
                "tx_bytes": s.get("tx", 0),
                "remote_ip": s.get("endpoint", ""),
            })
        if report:
            try:
                self.manager.report_endpoints(report)
            except Exception as e:  # noqa: BLE001
                self.log.debug("endpoint report failed: %s", e)

    def teardown(self) -> None:
        if self.dns:
            self.dns.stop()
