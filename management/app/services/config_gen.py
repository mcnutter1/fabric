"""Endpoint configuration generation — per-OS, per-protocol config + install steps."""
from __future__ import annotations

import base64
import io
import ipaddress
from dataclasses import dataclass

from ..models import Endpoint, Node
from ..models.enums import EndpointProtocol, EndpointOS


DNS_FABRIC = "100.64.0.1"  # fallback resolver address if no pool is configured


def _pool_gateway(cidr: str) -> str:
    """First host of an ingress node's endpoint pool — the address its fabric
    DNS resolver binds to and the one clients must query. Derived from the
    node's pool so the client config always points at the real resolver."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return str(next(net.hosts()))
    except Exception:  # noqa: BLE001
        return ""


@dataclass
class EndpointBundle:
    protocol: str
    os: str
    filename: str
    config_text: str
    qr_png_b64: str
    trusted_root_pem: str
    install_steps: list[str]


def render_wireguard_conf(endpoint: Endpoint, ingress: Node, private_key: str) -> str:
    allowed = "0.0.0.0/0, ::/0"  # full-tunnel; policy steers on the fabric side
    # The resolver binds to the ingress pool gateway (see the node's ingress
    # role); the client must send DNS there, not a hardcoded address, or its
    # queries hit an IP that isn't assigned to the node and get dropped.
    dns = _pool_gateway(ingress.endpoint_pool_cidr or "") or DNS_FABRIC
    return "\n".join([
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {endpoint.address}/32",
        f"DNS = {dns}",
        "",
        "[Peer]",
        f"PublicKey = {ingress.wg_public_key}",
        f"PresharedKey = {endpoint.preshared_key}" if endpoint.preshared_key else "",
        f"Endpoint = {ingress.public_endpoint}",
        f"AllowedIPs = {allowed}",
        "PersistentKeepalive = 25",
        "",
    ]).replace("\n\n\n", "\n\n")


def _qr_png_b64(text: str) -> str:
    """Render a QR code as base64 PNG.

    Prefers the pure-Python ``pypng`` backend so no Pillow / C build is needed;
    falls back to Pillow if it happens to be installed. QR is purely cosmetic —
    if neither backend is present we return "" and the caller hides the image.
    """
    try:
        import qrcode
        try:
            from qrcode.image.pure import PyPNGImage
            img = qrcode.make(text, image_factory=PyPNGImage)
        except Exception:
            img = qrcode.make(text)  # Pillow backend if available
        buf = io.BytesIO()
        img.save(buf)
        return base64.b64encode(buf.getvalue()).decode()
    except Exception:
        # QR backend not available — QR is optional, config still works.
        return ""


def _install_steps(os_name: str, protocol: str) -> list[str]:
    if protocol == EndpointProtocol.wireguard.value:
        common_trust = "Install the Fabric trusted-root bundle so inspected TLS is trusted."
        table = {
            EndpointOS.windows.value: [
                "Install the WireGuard client from wireguard.com/install.",
                "Import the downloaded .conf tunnel and activate it.",
                f"{common_trust} Double-click fabric-root.pem → Install to 'Trusted Root Certification Authorities'.",
            ],
            EndpointOS.macos.value: [
                "Install WireGuard from the Mac App Store.",
                "Import the .conf via 'Import tunnel(s) from file' and toggle on.",
                f"{common_trust} Open fabric-root.pem in Keychain Access → System → set 'Always Trust'.",
            ],
            EndpointOS.linux.value: [
                "sudo apt install wireguard  (or your distro equivalent).",
                "Place the .conf at /etc/wireguard/fabric.conf.",
                "sudo wg-quick up fabric   (enable at boot: sudo systemctl enable wg-quick@fabric).",
                f"{common_trust} sudo cp fabric-root.pem /usr/local/share/ca-certificates/fabric-root.crt && sudo update-ca-certificates.",
            ],
            EndpointOS.ios.value: [
                "Install WireGuard from the App Store.",
                "Scan the QR code shown in the console to import the tunnel.",
                f"{common_trust} Email/AirDrop fabric-root.pem, install the profile, then enable full trust in Settings → General → About → Certificate Trust Settings.",
            ],
            EndpointOS.android.value: [
                "Install WireGuard from Google Play.",
                "Scan the QR code to import the tunnel, then enable it.",
                f"{common_trust} Settings → Security → Encryption & credentials → Install a certificate → CA certificate → select fabric-root.pem.",
            ],
            EndpointOS.router.value: [
                "On OpenWrt: install the 'wireguard-tools' and 'luci-proto-wireguard' packages.",
                "Create a new WireGuard interface using the values in the .conf.",
                "Set AllowedIPs to 0.0.0.0/0 and add a firewall zone for the tunnel.",
            ],
        }
        return table.get(os_name, table[EndpointOS.linux.value])
    if protocol in (EndpointProtocol.ipsec_ikev2.value, EndpointProtocol.l2tp_ipsec.value):
        return [
            "Add a VPN profile of type IKEv2/IPsec (or L2TP/IPsec).",
            "Server: the ingress node public endpoint. Auth: machine certificate (provided) or EAP.",
            "Install the Fabric trusted-root bundle and the endpoint certificate.",
        ]
    if protocol == EndpointProtocol.openvpn.value:
        return [
            "Install the OpenVPN client for your platform.",
            "Import the provided .ovpn profile and connect.",
            "Install the Fabric trusted-root bundle for TLS inspection trust.",
        ]
    return ["Follow your platform's VPN import flow using the provided configuration."]


def build_bundle(endpoint: Endpoint, ingress: Node, private_key: str, trusted_root_pem: str) -> EndpointBundle:
    protocol = endpoint.protocol
    if protocol == EndpointProtocol.wireguard.value:
        config_text = render_wireguard_conf(endpoint, ingress, private_key)
        filename = f"fabric-{endpoint.name}.conf"
        qr = _qr_png_b64(config_text)
    else:
        # Non-WireGuard protocols: emit a descriptor the client tooling consumes.
        config_text = (
            f"# Fabric endpoint profile ({protocol})\n"
            f"server = {ingress.public_endpoint}\n"
            f"address = {endpoint.address}\n"
            f"protocol = {protocol}\n"
        )
        filename = f"fabric-{endpoint.name}.profile"
        qr = ""
    return EndpointBundle(
        protocol=protocol,
        os=endpoint.os,
        filename=filename,
        config_text=config_text,
        qr_png_b64=qr,
        trusted_root_pem=trusted_root_pem,
        install_steps=_install_steps(endpoint.os, protocol),
    )
