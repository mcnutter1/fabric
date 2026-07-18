"""Connector role — private network inbound/outbound gateway.

Bridges the fabric to a private/corporate network. Fabric endpoints reach the
advertised private CIDRs (outbound), and inbound-initiated flows from the
private side reach fabric endpoints. Observes traffic crossing into the private
network and reports it as flow telemetry.
"""
from __future__ import annotations

from .base import Role
from ..flowmon import FlowObserver
from ..policy import FlowCtx


class ConnectorRole(Role):
    name = "connector"

    def __init__(self, agent):
        super().__init__(agent)
        self.cidrs: list = []
        self.observer = FlowObserver(agent.sys)

    def _owned_cidrs(self, config: dict) -> list:
        """CIDRs this connector owns (advertised to the fabric)."""
        routing = config.get("routing", {})
        # Preferred: the manager echoes our own advertised CIDRs here.
        owned = list(routing.get("local_private_routes", []) or [])
        if owned:
            return owned
        # Fallback: routes tagged with our node id in the fabric-wide route map.
        for route in routing.get("private_routes", []) or []:
            if route.get("via_node") == self.state.node_id and route.get("cidr"):
                owned.append(route["cidr"])
        return owned or [c for c in config.get("private_routes", []) or []]

    def setup(self, config: dict) -> None:
        self.cidrs = self._owned_cidrs(config)
        if not self.cidrs:
            self.log.info("no private CIDRs assigned yet")
            return
        self.dp.setup_connector(self.cidrs)
        self.log.info("private connector active for %s", self.cidrs)

    def tick(self) -> None:
        if not self.telemetry or not self.cidrs:
            return
        for flow in self.observer.poll():
            if self._targets_private(flow.get("dst_ip", "")):
                self.telemetry.add_flow(self._enrich(flow))

    def teardown(self) -> None:
        self.dp.teardown_gateway()

    # ------------------------------------------------------------ internals
    def _targets_private(self, ip: str) -> bool:
        import ipaddress
        if not ip:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        for c in self.cidrs:
            try:
                if addr in ipaddress.ip_network(c, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _enrich(self, flow: dict) -> dict:
        verdict = "allowed"
        if self.policy:
            ctx = FlowCtx(
                src_ip=flow.get("src_ip", ""),
                dst_ip=flow.get("dst_ip", ""),
                dst_port=flow.get("dst_port", 0),
                protocol=flow.get("protocol", ""),
                node_roles=["private_connector"],
            )
            if self.policy.evaluate(ctx).action == "block":
                verdict = "denied"
        return {
            **flow,
            "node_id": self.state.node_id,
            "app": "private",
            "category": "private-network",
            "isp": "private",
            "country": "--",
            "verdict": verdict,
        }
