"""Egress role — the internet gateway.

Responsibilities:
  * Forward + SNAT fabric traffic to the internet, optionally round-robined
    across a pool of public egress IPs (dynamic internet egress).
  * Fetch the inspection (MITM) CA and stand up TLS inspection so `inspect`
    policy verdicts can decrypt + reclassify.
  * Observe real egress connections (conntrack), classify them (GeoIP/ASN/ISP),
    apply policy verdicts locally, and stream them as flow telemetry.
"""
from __future__ import annotations

from .base import Role
from ..flowmon import FlowObserver
from ..inspect import load_inspector
from ..policy import FlowCtx


class EgressRole(Role):
    name = "egress"

    def __init__(self, agent):
        super().__init__(agent)
        self.wan = ""
        self.egress_ips: list = []
        self.observer = FlowObserver(agent.sys)
        self._inspector_ready = False

    def setup(self, config: dict) -> None:
        self.egress_ips = config.get("egress_ip_pool", []) or []
        # Endpoint pools can be arbitrary operator CIDRs; register them so
        # client-originated connections aren't filtered out of flow telemetry.
        pools = list((config.get("routing", {}) or {}).get("endpoint_pools", []) or [])
        self.wan = self.dp.setup_egress(egress_ips=self.egress_ips, src_cidrs=pools)
        self.observer.set_sources(pools)
        self.log.info("internet gateway active via %s (egress pool: %s)",
                      self.wan, self.egress_ips or "wan primary IP")

        # Stand up TLS inspection once (needs the MITM CA from the manager).
        if not self._inspector_ready:
            mitm = self.manager.get_mitm_ca()
            self.agent.inspector = load_inspector(mitm)
            self._inspector_ready = self.agent.inspector is not None

    def tick(self) -> None:
        if not self.telemetry:
            return
        for flow in self.observer.poll():
            enriched = self._enrich(flow)
            self.telemetry.add_flow(enriched)

    def teardown(self) -> None:
        self.dp.teardown_gateway()

    # ------------------------------------------------------------ internals
    def _enrich(self, flow: dict) -> dict:
        ipinfo = self.classifier.classify_ip(flow.get("dst_ip", ""))
        category = "uncategorized"
        verdict = "allowed"
        risk = 0
        if self.policy:
            ctx = FlowCtx(
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=flow.get("dst_port", 0),
                protocol=flow.get("protocol", ""),
                country=ipinfo.get("country", ""),
                asn=ipinfo.get("asn", 0),
                node_roles=["egress"],
            )
            decision = self.policy.evaluate(ctx)
            if decision.action == "block":
                verdict = "denied"
            elif decision.action == "inspect":
                verdict = "inspected"
            risk = self.classifier.risk_for(category)
        egress_ip = self.egress_ips[0] if self.egress_ips else ""
        return {
            **flow,
            "node_id": self.state.node_id,
            "egress_node_id": self.state.node_id,
            "egress_ip": egress_ip,
            "category": category,
            "country": ipinfo.get("country", ""),
            "asn": ipinfo.get("asn", 0),
            "isp": ipinfo.get("isp", ""),
            "geo": ipinfo.get("geo", {}),
            "verdict": verdict,
            "risk": risk,
        }
