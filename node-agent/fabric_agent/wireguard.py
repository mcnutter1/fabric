"""WireGuard key + config helpers for the agent (pure-Python keygen)."""
from __future__ import annotations

import base64

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[str, str]:
    """Return (private_b64, public_b64) WireGuard keys."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def render_wg_conf(state, config: dict) -> str:
    """Render a wg-quick style config from the manager-provided node config.

    We deliberately set `Table = off` — routing is programmed separately via
    policy routing (see routing.py) so that per-flow steering (internet ->
    egress peer, private CIDR -> connector) can be applied.
    """
    iface = config.get("interface", {})
    addr = iface.get("address", "")
    port = iface.get("listen_port", state.wg_listen_port)

    lines = ["[Interface]"]
    if addr:
        lines.append(f"Address = {addr}")
    lines.append(f"ListenPort = {port}")
    lines.append(f"PrivateKey = {state.wg_private_key}")
    lines.append("Table = off")
    lines.append("")

    for peer in config.get("peers", []):
        if not peer.get("public_key"):
            continue
        lines.append(f"# {peer.get('name', peer.get('node_id'))} [{','.join(peer.get('roles') or [])}]")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer['public_key']}")
        allowed = peer.get("allowed_ips") or []
        if allowed:
            lines.append(f"AllowedIPs = {', '.join(allowed)}")
        if peer.get("endpoint"):
            lines.append(f"Endpoint = {peer['endpoint']}")
        lines.append(f"PersistentKeepalive = {peer.get('persistent_keepalive', 25)}")
        lines.append("")

    return "\n".join(lines) + "\n"
