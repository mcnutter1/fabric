"""Enumerations shared across models and schemas."""
from __future__ import annotations

import enum


class NodeRole(str, enum.Enum):
    ingress = "ingress"          # terminates endpoint/client tunnels
    egress = "egress"            # sends traffic to the internet
    private_connector = "private_connector"  # bridges a private network
    relay = "relay"             # pure fabric transit / HA


class NodeStatus(str, enum.Enum):
    pending = "pending"          # created, awaiting pairing
    pairing = "pairing"          # pairing code issued
    online = "online"
    degraded = "degraded"
    offline = "offline"
    disabled = "disabled"


class LinkStatus(str, enum.Enum):
    up = "up"
    degraded = "degraded"
    down = "down"


class EndpointProtocol(str, enum.Enum):
    wireguard = "wireguard"
    ipsec_ikev2 = "ipsec_ikev2"
    l2tp_ipsec = "l2tp_ipsec"
    openvpn = "openvpn"


class EndpointOS(str, enum.Enum):
    windows = "windows"
    macos = "macos"
    linux = "linux"
    ios = "ios"
    android = "android"
    router = "router"


class EndpointStatus(str, enum.Enum):
    provisioned = "provisioned"
    active = "active"
    idle = "idle"
    revoked = "revoked"


class CertKind(str, enum.Enum):
    root_ca = "root_ca"
    infra_ca = "infra_ca"
    endpoint_ca = "endpoint_ca"
    mitm_ca = "mitm_ca"
    node = "node"
    endpoint = "endpoint"
    leaf = "leaf"


class PolicyAction(str, enum.Enum):
    allow = "allow"
    deny = "deny"
    inspect = "inspect"      # force TLS MITM
    bypass = "bypass"        # never inspect
    steer = "steer"          # choose egress / connector
    redirect = "redirect"    # DNS/HTTP hijack to URL
    block_page = "block_page"  # inject a message page
    log = "log"
    alert = "alert"


class FlowVerdict(str, enum.Enum):
    allowed = "allowed"
    denied = "denied"
    inspected = "inspected"
    redirected = "redirected"


class DnsAction(str, enum.Enum):
    resolve = "resolve"
    block = "block"
    redirect = "redirect"
    sinkhole = "sinkhole"
