"""WireGuard key/address helpers and config templating (pure-python, no wg binary)."""
from __future__ import annotations

import base64
import ipaddress
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


@dataclass
class WGKeypair:
    private_key: str
    public_key: str


def generate_keypair() -> WGKeypair:
    """Generate a Curve25519 WireGuard keypair (base64, standard wg format)."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return WGKeypair(
        private_key=base64.b64encode(priv_raw).decode(),
        public_key=base64.b64encode(pub_raw).decode(),
    )


def generate_preshared_key() -> str:
    import os
    return base64.b64encode(os.urandom(32)).decode()


def pubkey_from_private(private_key_b64: str) -> str:
    raw = base64.b64decode(private_key_b64)
    priv = X25519PrivateKey.from_private_bytes(raw)
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.b64encode(pub_raw).decode()


class AddressAllocator:
    """Deterministic-ish allocator over a CIDR that skips already-used addresses."""

    def __init__(self, cidr: str):
        self.network = ipaddress.ip_network(cidr, strict=False)

    def first_host(self) -> str:
        return str(next(self.network.hosts()))

    def allocate(self, used: set[str]) -> str:
        for host in self.network.hosts():
            s = str(host)
            if s not in used:
                return s
        raise RuntimeError(f"address pool {self.network} exhausted")


def render_peer(public_key: str, endpoint: str, allowed_ips: list[str],
                preshared_key: str = "", keepalive: int = 25) -> str:
    lines = ["[Peer]", f"PublicKey = {public_key}"]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    if endpoint:
        lines.append(f"Endpoint = {endpoint}")
    lines.append(f"AllowedIPs = {', '.join(allowed_ips)}")
    if keepalive:
        lines.append(f"PersistentKeepalive = {keepalive}")
    return "\n".join(lines)
