"""Data-plane programming: apply the WireGuard interface, policy routing, NAT.

The manager hands us a `config` dict with peers + routing hints. We translate it
into concrete `ip`/`wg`/`iptables`/`nft` operations. All operations are
idempotent-ish and safe to re-run on every config change.
"""
from __future__ import annotations

import logging
import re

from typing import Optional

from .system import System

log = logging.getLogger("fabric.agent.dp")

RT_TABLE = "51820"      # dedicated routing table for fabric-steered traffic
FWMARK = "0x51820"
FAB_POST = "FABRIC_POST"   # our nat POSTROUTING chain
FAB_FWD = "FABRIC_FWD"     # our filter FORWARD chain
FABRIC_CGNAT = "100.64.0.0/10"  # covers endpoint (100.64/12) + node (100.96/12) ranges


class DataPlane:
    def __init__(self, iface: str, system: System):
        self.iface = iface
        self.sys = system

    # ------------------------------------------------------------------ wg
    def apply_wireguard(self, conf_path) -> None:
        """Bring up / sync the WireGuard interface from a wg-quick config file."""
        s = self.sys
        # Create interface only if missing (avoids a noisy "File exists" warning
        # on every reconfigure, since the interface persists across restarts).
        existing = s.run(["ip", "link", "show", "dev", self.iface], capture=True)
        if not existing:
            s.run(["ip", "link", "add", "dev", self.iface, "type", "wireguard"])
        # Sync configuration (strip wg-quick-only keys for `wg syncconf`). Feed
        # the config to wg over stdin rather than a temp file path, so it never
        # depends on the setconf file's ownership/permissions.
        stripped = self._strip_for_setconf(conf_path)
        if stripped:
            s.run(["wg", "syncconf", self.iface, "/dev/stdin"], input=stripped)
        # Address + up.
        # (Address lines are applied explicitly below by the caller via set_address.)
        s.run(["ip", "link", "set", "up", "dev", self.iface])

    def set_address(self, cidr: str) -> None:
        if not cidr:
            return
        self.sys.run(["ip", "address", "replace", cidr, "dev", self.iface])

    def _strip_for_setconf(self, conf_path):
        """wg setconf/syncconf rejects wg-quick keys (Address/Table). Return a
        config string with only [Interface]/[Peer] cryptographic keys, suitable
        for feeding to `wg syncconf` over stdin."""
        try:
            text = conf_path.read_text()
        except Exception:
            return None
        keep_iface = {"privatekey", "listenport", "fwmark"}
        keep_peer = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
        out, section = [], None
        for line in text.splitlines():
            st = line.strip()
            if not st or st.startswith("#"):
                out.append(line)
                continue
            if st.lower() == "[interface]":
                section = "iface"; out.append(line); continue
            if st.lower() == "[peer]":
                section = "peer"; out.append(line); continue
            key = st.split("=", 1)[0].strip().lower()
            if section == "iface" and key in keep_iface:
                out.append(line)
            elif section == "peer" and key in keep_peer:
                out.append(line)
        return "\n".join(out) + "\n"

    # ------------------------------------------------------------ routing
    def apply_routing(self, routing: dict) -> None:
        """Program policy routing from the manager's routing hints.

        Strategy: a dedicated table (51820) holds fabric routes. An `ip rule`
        directs marked / sourced traffic into it. Internet default goes via the
        chosen egress peer; private CIDRs go via their connector peer.
        """
        s = self.sys
        # Every fabric node forwards packets between the tunnel and elsewhere
        # (ingress: client -> fabric peer; connector: fabric -> private LAN;
        # egress: fabric -> internet). Without this the kernel silently drops
        # forwarded client traffic, so nothing traverses the fabric and no
        # flow/DNS telemetry is ever produced. Enable it on every node, not
        # just egress.
        self.enable_ip_forward()

        # Ensure exactly one `ip rule` routes fabric-marked traffic via our
        # table. `ip rule add` appends a fresh copy on every apply, so strip any
        # existing duplicates first (this both fixes the leak and reconciles
        # nodes that have accumulated hundreds of stale copies).
        existing = s.run(["ip", "rule", "show"], capture=True) or ""
        dups = existing.count(f"fwmark {FWMARK} lookup {RT_TABLE}")
        for _ in range(dups):
            s.run(["ip", "rule", "del", "fwmark", FWMARK, "table", RT_TABLE])
        s.run(["ip", "rule", "add", "fwmark", FWMARK, "table", RT_TABLE])

        # Flush our table so stale routes don't linger.
        s.run(["ip", "route", "flush", "table", RT_TABLE])

        egress = routing.get("egress")
        if egress and egress.get("peer_addr"):
            # Default route -> egress peer over the fabric interface.
            s.run(["ip", "route", "add", "default", "dev", self.iface, "table", RT_TABLE])

        for route in routing.get("private_routes", []) or []:
            cidr = route.get("cidr")
            if cidr:
                s.run(["ip", "route", "add", cidr, "dev", self.iface, "table", RT_TABLE])

        pool = routing.get("endpoint_pool")
        if pool:
            s.run(["ip", "route", "add", pool, "dev", self.iface, "table", RT_TABLE])

    # ------------------------------------------------------------ NAT / gateway
    def enable_ip_forward(self) -> None:
        self.sys.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        self.sys.run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])

    def wan_interface(self) -> str:
        """Best-effort detection of the interface that owns the default route."""
        out = self.sys.run(["ip", "route", "show", "default"], capture=True) or ""
        m = re.search(r"default .* dev (\S+)", out)
        if m and m.group(1) != self.iface:
            return m.group(1)
        return "eth0"

    def _ensure_chains(self) -> None:
        """Create dedicated FABRIC chains (idempotent) so we own + can flush our rules."""
        s = self.sys
        # nat POSTROUTING -> FABRIC_POST
        s.run(["iptables", "-t", "nat", "-N", FAB_POST])
        if not self._rule_exists(["iptables", "-t", "nat", "-C", "POSTROUTING", "-j", FAB_POST]):
            s.run(["iptables", "-t", "nat", "-A", "POSTROUTING", "-j", FAB_POST])
        # filter FORWARD -> FABRIC_FWD
        s.run(["iptables", "-N", FAB_FWD])
        if not self._rule_exists(["iptables", "-C", "FORWARD", "-j", FAB_FWD]):
            s.run(["iptables", "-A", "FORWARD", "-j", FAB_FWD])

    def _rule_exists(self, check_args: list[str]) -> bool:
        # `-C` returns non-zero when absent; System.run swallows that (returns None),
        # so we run directly to inspect the code. In dry-run assume it doesn't exist.
        if self.sys.dry_run or not self.sys.have(check_args[0]):
            return False
        import subprocess
        return subprocess.run(check_args, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0

    def _flush_fabric_chains(self) -> None:
        self.sys.run(["iptables", "-t", "nat", "-F", FAB_POST])
        self.sys.run(["iptables", "-F", FAB_FWD])

    def setup_egress(self, wan: str = "", egress_ips: Optional[list] = None,
                     src_cidr: str = FABRIC_CGNAT) -> str:
        """Program an internet-egress gateway.

        Forwards fabric-sourced traffic out `wan` and SNATs it. If an egress IP
        pool is supplied, connections are round-robined across those addresses
        (dynamic internet egress); otherwise MASQUERADE uses the WAN primary IP.
        """
        s = self.sys
        wan = wan or self.wan_interface()
        self.enable_ip_forward()
        self._ensure_chains()
        self._flush_fabric_chains()

        # Forwarding: fabric -> internet and established back.
        s.run(["iptables", "-A", FAB_FWD, "-i", self.iface, "-o", wan, "-j", "ACCEPT"])
        s.run(["iptables", "-A", FAB_FWD, "-i", wan, "-o", self.iface,
               "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        # Clamp MSS to path MTU for tunnelled TCP.
        s.run(["iptables", "-A", FAB_FWD, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
               "-j", "TCPMSS", "--clamp-mss-to-pmtu"])

        egress_ips = [ip for ip in (egress_ips or []) if ip]
        if egress_ips:
            self.bind_egress_ips(egress_ips, wan)
            n = len(egress_ips)
            for i, ip in enumerate(egress_ips):
                # Round-robin new connections across the pool via the statistic module.
                s.run(["iptables", "-t", "nat", "-A", FAB_POST, "-s", src_cidr, "-o", wan,
                       "-m", "statistic", "--mode", "nth", "--every", str(n - i), "--packet", "0",
                       "-j", "SNAT", "--to-source", ip])
        else:
            s.run(["iptables", "-t", "nat", "-A", FAB_POST, "-s", src_cidr, "-o", wan, "-j", "MASQUERADE"])
        log.info("egress gateway ready (wan=%s, egress_ips=%s)", wan, egress_ips or "masquerade")
        return wan

    def bind_egress_ips(self, ips: list, wan: str) -> None:
        """Attach additional public egress IPs to the WAN interface (pool)."""
        for ip in ips:
            addr = ip if "/" in ip else f"{ip}/32"
            self.sys.run(["ip", "address", "replace", addr, "dev", wan])

    def setup_connector(self, cidrs: list, wan: str = "") -> None:
        """Program a private-network connector (inbound + outbound).

        Fabric endpoints reach the private CIDRs (outbound) via SNAT onto the
        connector's private-side address; return + inbound-initiated flows to
        endpoints are allowed through established conntrack.
        """
        s = self.sys
        wan = wan or self.wan_interface()
        self.enable_ip_forward()
        self._ensure_chains()
        for cidr in cidrs:
            if not cidr:
                continue
            # Outbound: fabric -> private CIDR.
            s.run(["iptables", "-A", FAB_FWD, "-i", self.iface, "-d", cidr, "-j", "ACCEPT"])
            # Inbound: private -> fabric endpoints (established/related + initiated).
            s.run(["iptables", "-A", FAB_FWD, "-o", self.iface, "-s", cidr, "-j", "ACCEPT"])
            # SNAT fabric traffic onto the private network so hosts route replies back to us.
            s.run(["iptables", "-t", "nat", "-A", FAB_POST, "-s", FABRIC_CGNAT, "-d", cidr,
                   "-o", wan, "-j", "MASQUERADE"])
        log.info("connector gateway ready (private_cidrs=%s wan=%s)", cidrs, wan)

    def add_inbound_dnat(self, proto: str, dport: int, to_addr: str, wan: str = "") -> None:
        """Publish a private service inbound: WAN:dport -> fabric endpoint."""
        wan = wan or self.wan_interface()
        self.sys.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", wan,
                      "-p", proto, "--dport", str(dport), "-j", "DNAT", "--to-destination", to_addr])
        self.sys.run(["iptables", "-A", FAB_FWD, "-p", proto, "-d", to_addr.split(":")[0],
                      "--dport", str(to_addr.split(":")[1] if ":" in to_addr else dport), "-j", "ACCEPT"])

    def teardown_gateway(self) -> None:
        """Remove all FABRIC nat/forward rules (clean shutdown)."""
        s = self.sys
        s.run(["iptables", "-t", "nat", "-D", "POSTROUTING", "-j", FAB_POST])
        s.run(["iptables", "-t", "nat", "-F", FAB_POST])
        s.run(["iptables", "-t", "nat", "-X", FAB_POST])
        s.run(["iptables", "-D", "FORWARD", "-j", FAB_FWD])
        s.run(["iptables", "-F", FAB_FWD])
        s.run(["iptables", "-X", FAB_FWD])

    # ------------------------------------------------------------ stats
    def wg_link_stats(self) -> dict[str, dict]:
        """Parse `wg show <iface> dump` into {public_key: {rx, tx, handshake}}."""
        out = self.sys.run(["wg", "show", self.iface, "dump"], capture=True)
        stats: dict[str, dict] = {}
        if not out:
            return stats
        for line in out.strip().splitlines()[1:]:  # first line is interface
            cols = line.split("\t")
            if len(cols) < 8:
                continue
            pubkey = cols[0]
            try:
                last_hs = int(cols[4])
                rx = int(cols[5])
                tx = int(cols[6])
            except ValueError:
                continue
            endpoint = cols[2] if cols[2] and cols[2] != "(none)" else ""
            stats[pubkey] = {
                "rx": rx, "tx": tx,
                "endpoint": endpoint,
                "last_handshake": last_hs,
                "last_handshake_ok": last_hs > 0,
            }
        return stats
