"""Fabric orchestrator — computes the WireGuard mesh and per-node config.

The manager owns topology. For each node it produces a `NodeConfig` describing:
 * the wg interface (address, port),
 * the full-mesh peer list (pubkey, endpoint, allowed_ips, keepalive),
 * routing/steering hints (which peer owns internet egress, which peers own
   which private CIDRs, the ingress endpoint pool),
 * active role modules (dns, inspection).

Nodes run `Table = off` on their fabric interface and install policy routing
from these hints, so a packet's next fabric hop is chosen by destination/policy
(internet -> egress peer, private CIDR -> owning connector, endpoint -> ingress).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Node, FabricLink, Endpoint
from ..models.enums import NodeRole, NodeStatus, LinkStatus


def _roles(node: Node) -> set[str]:
    return set(node.roles or [])


class FabricOrchestrator:
    def __init__(self, db: Session):
        self.db = db

    def _active_nodes(self) -> list[Node]:
        return list(
            self.db.scalars(
                select(Node).where(Node.status.in_([NodeStatus.online.value, NodeStatus.degraded.value]))
            )
        )

    def _healthy_egress(self) -> list[Node]:
        return [
            n for n in self._active_nodes()
            if NodeRole.egress.value in _roles(n) and n.status == NodeStatus.online.value
        ]

    # ------------------------------------------------------------------ mesh
    def compute_links(self) -> None:
        """Ensure a FabricLink row exists for every node pair (full mesh)."""
        nodes = list(self.db.scalars(select(Node)))
        existing = {
            tuple(sorted((l.node_a, l.node_b))): l
            for l in self.db.scalars(select(FabricLink))
        }
        for i, a in enumerate(nodes):
            for b in nodes[i + 1:]:
                key = tuple(sorted((a.id, b.id)))
                if key not in existing:
                    self.db.add(FabricLink(node_a=key[0], node_b=key[1], status=LinkStatus.down.value))
        self.db.commit()

    def topology(self) -> dict:
        """Serialised topology for the UI map."""
        nodes = list(self.db.scalars(select(Node)))
        links = list(self.db.scalars(select(FabricLink)))
        return {
            "nodes": [
                {
                    "id": n.id,
                    "name": n.name,
                    "roles": n.roles,
                    "region": n.region,
                    "status": n.status,
                    "fabric_addr": n.fabric_addr,
                    "public_endpoint": n.public_endpoint,
                    "health": n.health,
                }
                for n in nodes
            ],
            "links": [
                {
                    "a": l.node_a, "b": l.node_b, "status": l.status,
                    "latency_ms": l.latency_ms, "loss_pct": l.loss_pct,
                    "tx_bytes": l.tx_bytes, "rx_bytes": l.rx_bytes,
                }
                for l in links
            ],
        }

    # ------------------------------------------------------------------ per-node config
    def compute_node_config(self, node: Node) -> dict:
        peers = []
        others = [n for n in self._active_nodes() if n.id != node.id and n.wg_public_key]

        # Choose this node's primary internet egress (skip if this node *is* egress).
        egress_choice: Optional[Node] = None
        if NodeRole.egress.value not in _roles(node):
            egress_choice = self._select_egress_for(node)

        for peer in others:
            allowed = []
            if peer.fabric_addr:
                allowed.append(f"{peer.fabric_addr}/32")
            proles = _roles(peer)
            # Ingress peers own their endpoint pool (return traffic to clients).
            if NodeRole.ingress.value in proles and peer.endpoint_pool_cidr:
                allowed.append(peer.endpoint_pool_cidr)
            # Connector peers own their advertised private CIDRs.
            if NodeRole.private_connector.value in proles:
                allowed.extend(peer.private_routes or [])
            # The chosen egress peer additionally owns the default route.
            if egress_choice and peer.id == egress_choice.id:
                allowed.extend(["0.0.0.0/0", "::/0"])
            peers.append({
                "node_id": peer.id,
                "name": peer.name,
                "roles": peer.roles,
                "public_key": peer.wg_public_key,
                "endpoint": peer.public_endpoint,
                "allowed_ips": _dedupe(allowed),
                "persistent_keepalive": 25,
            })

        routing = {
            "endpoint_pool": node.endpoint_pool_cidr or None,
            "egress": (
                {"via_node": egress_choice.id, "peer_addr": egress_choice.fabric_addr}
                if egress_choice else None
            ),
            "private_routes": self._private_route_map(node),
            "local_private_routes": list(node.private_routes or []),
            "table": "off",
            "fwmark": 51820,
        }

        config = {
            "node_id": node.id,
            "name": node.name,
            "roles": node.roles,
            "interface": {
                "address": f"{node.fabric_addr}/12" if node.fabric_addr else "",
                "listen_port": node.wg_listen_port or settings.wg_port,
            },
            "peers": peers,
            "routing": routing,
            "egress_ip_pool": node.egress_ip_pool or [],
            "target_version": node.target_version or node.version,
        }
        config["version"] = self._config_hash(config)
        return config

    def _select_egress_for(self, node: Node) -> Optional[Node]:
        """Pick a healthy egress node, preferring same region, else lowest link latency."""
        candidates = self._healthy_egress()
        if not candidates:
            return None
        same_region = [n for n in candidates if node.region and n.region == node.region]
        pool = same_region or candidates
        # Prefer the lowest-latency link from this node.
        links = {
            tuple(sorted((l.node_a, l.node_b))): l
            for l in self.db.scalars(select(FabricLink))
        }

        def latency(n: Node) -> float:
            l = links.get(tuple(sorted((node.id, n.id))))
            return l.latency_ms if l and l.status == LinkStatus.up.value else 9999.0

        return sorted(pool, key=latency)[0]

    def _private_route_map(self, node: Node) -> list[dict]:
        routes = []
        for peer in self._active_nodes():
            if peer.id == node.id:
                continue
            if NodeRole.private_connector.value in _roles(peer):
                for cidr in peer.private_routes or []:
                    routes.append({"cidr": cidr, "via_node": peer.id, "peer_addr": peer.fabric_addr})
        return routes

    @staticmethod
    def _config_hash(config: dict) -> str:
        payload = json.dumps(config, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _dedupe(items: list[str]) -> list[str]:
    seen: list[str] = []
    for i in items:
        if i not in seen:
            seen.append(i)
    return seen
