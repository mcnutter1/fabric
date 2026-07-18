"""Flow observation via conntrack.

Egress and connector nodes get real traffic visibility by reading the kernel
connection tracking table (`conntrack -L`, falling back to
`/proc/net/nf_conntrack`). New connections since the last poll are emitted as
flow records so the manager/console see live traffic even without a full
packet-inspection proxy.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import time
from typing import Iterator, Optional

from .system import System

log = logging.getLogger("fabric.agent.flowmon")

_KV = re.compile(r"(\w+)=(\S+)")

# The fabric CGNAT supernet (node addrs + default CGNAT pools). Always treated
# as a fabric source; operators may additionally use arbitrary private CIDRs for
# their endpoint pools (e.g. 10.10.120.0/24), which are supplied at runtime.
FABRIC_SUPERNET = "100.64.0.0/10"


class FlowObserver:
    def __init__(self, system: System, src_cidrs: Optional[list] = None):
        self.sys = system
        self._seen: dict[tuple, float] = {}
        self._ttl = 300  # forget a flow tuple after 5 min so long flows re-report
        self._src_nets: list = []
        self.set_sources(src_cidrs or [FABRIC_SUPERNET])

    def set_sources(self, cidrs: list) -> None:
        """Define which source CIDRs count as fabric-originated. Endpoint pools
        can be any operator-chosen CIDR, so we match by network membership
        rather than fixed string prefixes. The fabric supernet is always
        included as a safety net."""
        nets = []
        for c in list(cidrs or []) + [FABRIC_SUPERNET]:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            if net not in nets:
                nets.append(net)
        self._src_nets = nets

    def _from_fabric(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._src_nets)

    def poll(self) -> list[dict]:
        """Return flow dicts for connections first seen since the previous poll."""
        raw = self._read()
        now = time.time()
        # Expire old tuples.
        for k, ts in list(self._seen.items()):
            if now - ts > self._ttl:
                self._seen.pop(k, None)

        flows: list[dict] = []
        for conn in raw:
            src, dst = conn.get("src", ""), conn.get("dst", "")
            sport, dport = conn.get("sport", "0"), conn.get("dport", "0")
            proto = conn.get("proto", "")
            # Only report fabric-originated egress connections.
            if not self._from_fabric(src):
                continue
            if self._from_fabric(dst):
                continue  # intra-fabric, skip
            key = (src, dst, dport, proto)
            if key in self._seen:
                self._seen[key] = now
                continue
            self._seen[key] = now
            flows.append({
                "src_ip": src, "dst_ip": dst,
                "dst_port": int(dport) if dport.isdigit() else 0,
                "protocol": proto,
                "tx_bytes": int(conn.get("tx_bytes", 0)),
                "rx_bytes": int(conn.get("rx_bytes", 0)),
            })
        return flows

    # ------------------------------------------------------------ readers
    def _read(self) -> list[dict]:
        if self.sys.have("conntrack"):
            out = self.sys.run(["conntrack", "-L", "-o", "extended"], capture=True)
            if out:
                return list(self._parse_conntrack(out))
        # Fallback to procfs.
        try:
            with open("/proc/net/nf_conntrack") as fh:
                return list(self._parse_conntrack(fh.read()))
        except Exception:
            return []

    def _parse_conntrack(self, text: str) -> Iterator[dict]:
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            proto = "tcp" if " tcp " in f" {line} " else ("udp" if " udp " in f" {line} " else "")
            if not proto:
                # protocol is usually the first word (proto num aside)
                proto = parts[0] if parts[0] in ("tcp", "udp", "icmp") else ""
            kvs = dict(_KV.findall(line))
            # The first src/dst pair is the original direction; bytes appear per direction.
            # conntrack -o extended emits bytes= for each tuple.
            src = kvs.get("src", "")
            dst = kvs.get("dst", "")
            sport = kvs.get("sport", "0")
            dport = kvs.get("dport", "0")
            # bytes: original then reply. re.findall grabs the first occurrence only,
            # so pull all byte counters explicitly.
            byte_vals = re.findall(r"bytes=(\d+)", line)
            tx = int(byte_vals[0]) if len(byte_vals) >= 1 else 0
            rx = int(byte_vals[1]) if len(byte_vals) >= 2 else 0
            if not (src and dst):
                continue
            yield {"proto": proto, "src": src, "dst": dst, "sport": sport,
                   "dport": dport, "tx_bytes": tx, "rx_bytes": rx}
