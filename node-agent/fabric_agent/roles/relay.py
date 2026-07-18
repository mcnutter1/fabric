"""Relay role — transit-only fabric hop for HA / hub-and-spoke paths.

A relay just forwards fabric traffic between peers; it neither exits to the
internet nor bridges a private network. It only enables forwarding across the
fabric interface.
"""
from __future__ import annotations

from .base import Role


class RelayRole(Role):
    name = "relay"

    def setup(self, config: dict) -> None:
        self.dp.enable_ip_forward()
        self.dp._ensure_chains()
        # Allow transit between fabric peers on the WireGuard interface.
        self.dp.sys.run(["iptables", "-A", "FABRIC_FWD", "-i", self.dp.iface,
                         "-o", self.dp.iface, "-j", "ACCEPT"])
        self.log.info("relay transit active on %s", self.dp.iface)
