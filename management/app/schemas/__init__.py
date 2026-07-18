"""Pydantic request/response schemas."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from pydantic import BaseModel, Field, ConfigDict


# ------------------------------------------------------------------ Nodes
class NodeCreate(BaseModel):
    # Onboarding is intentionally minimal: identity + intent only. All
    # network-specific config (public endpoint, pools, routes) is pushed
    # after the node registers itself online, via NodeUpdate.
    name: str
    roles: list[str] = Field(default_factory=list)
    region: str = ""


class NodeUpdate(BaseModel):
    name: Optional[str] = None
    roles: Optional[list[str]] = None
    region: Optional[str] = None
    public_endpoint: Optional[str] = None
    endpoint_pool_cidr: Optional[str] = None
    egress_ip_pool: Optional[list[str]] = None
    private_routes: Optional[list[str]] = None
    target_version: Optional[str] = None
    status: Optional[str] = None


class NodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    roles: list[str]
    region: str
    status: str
    fabric_addr: str
    wg_public_key: str
    wg_listen_port: int
    public_endpoint: str
    hostname: str
    endpoint_pool_cidr: str
    egress_ip_pool: list[str]
    private_routes: list[str]
    version: str
    target_version: str
    last_seen: Optional[dt.datetime]
    health: dict


class PairingOut(BaseModel):
    code: str
    expires_at: dt.datetime
    install_command: str


class NodeEnrollRequest(BaseModel):
    code: str
    wg_public_key: str
    hostname: str = ""
    version: str = ""
    advertised_endpoint: str = ""  # public ip:port the node believes it has


class NodeEnrollResponse(BaseModel):
    node_id: str
    node_token: str
    fabric_addr: str
    wg_listen_port: int
    roles: list[str]
    cert_pem: str
    key_pem: str
    ca_chain_pem: str
    manager_ca_pem: str


# ------------------------------------------------------------------ Node runtime
class NodeHeartbeat(BaseModel):
    version: str = ""
    health: dict = Field(default_factory=dict)
    links: list[dict] = Field(default_factory=list)  # [{peer_id, latency_ms, loss_pct, tx, rx, last_handshake}]


class FlowIngest(BaseModel):
    endpoint_id: str = ""
    user_uid: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: str = ""
    sni: str = ""
    domain: str = ""
    category: str = ""
    app: str = ""
    country: str = ""
    asn: int = 0
    isp: str = ""
    ja3: str = ""
    verdict: str = "allowed"
    egress_node_id: str = ""
    egress_ip: str = ""
    risk: int = 0
    tx_bytes: int = 0
    rx_bytes: int = 0
    duration_ms: int = 0
    meta: dict = Field(default_factory=dict)
    geo: dict = Field(default_factory=dict)


class DnsIngest(BaseModel):
    endpoint_id: str = ""
    user_uid: str = ""
    client_ip: str = ""
    qname: str
    qtype: str = "A"
    answer: str = ""
    category: str = ""
    action: str = "resolve"
    latency_ms: float = 0
    meta: dict = Field(default_factory=dict)


class EndpointStatIngest(BaseModel):
    """Per-endpoint WireGuard connection stats reported by an ingress node."""
    endpoint_id: str = ""
    wg_public_key: str = ""
    last_handshake: int = 0     # unix epoch seconds (0 = never)
    rx_bytes: int = 0
    tx_bytes: int = 0
    remote_ip: str = ""         # host:port the client dialed from


# ------------------------------------------------------------------ Endpoints
class EndpointCreate(BaseModel):
    name: str
    user_uid: str = ""
    user_email: str = ""
    user_name: str = ""
    protocol: str = "wireguard"
    os: str = "windows"
    ingress_node_id: Optional[str] = None
    inspect_tls: bool = True
    tags: list[str] = Field(default_factory=list)


class EndpointUpdate(BaseModel):
    """Partial edit of an endpoint. Any field left unset is untouched."""
    name: Optional[str] = None
    user_uid: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    protocol: Optional[str] = None
    os: Optional[str] = None
    ingress_node_id: Optional[str] = None
    inspect_tls: Optional[bool] = None
    tags: Optional[list[str]] = None


class EndpointOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    user_uid: str
    user_email: str
    user_name: str
    protocol: str
    os: str
    status: str
    ingress_node_id: Optional[str]
    address: str
    wg_public_key: str
    inspect_tls: bool
    tags: list[str]
    last_seen: Optional[dt.datetime]


class EndpointBundleOut(BaseModel):
    endpoint: EndpointOut
    protocol: str
    os: str
    filename: str
    config_text: str
    qr_png_b64: str
    trusted_root_pem: str
    install_steps: list[str]


# ------------------------------------------------------------------ Policy
class PolicyRuleIn(BaseModel):
    name: str = ""
    enabled: bool = True
    order: int = 0
    match_roles: list[str] = Field(default_factory=list)
    match_users: list[str] = Field(default_factory=list)
    match_src_cidrs: list[str] = Field(default_factory=list)
    match_endpoints: list[str] = Field(default_factory=list)
    match_node_roles: list[str] = Field(default_factory=list)
    match_dst_cidrs: list[str] = Field(default_factory=list)
    match_domains: list[str] = Field(default_factory=list)
    match_categories: list[str] = Field(default_factory=list)
    match_ports: list = Field(default_factory=list)
    match_protocols: list[str] = Field(default_factory=list)
    match_countries: list[str] = Field(default_factory=list)
    match_asns: list = Field(default_factory=list)
    match_time: dict = Field(default_factory=dict)
    action: str = "allow"
    action_params: dict = Field(default_factory=dict)


class PolicyRuleOut(PolicyRuleIn):
    model_config = ConfigDict(from_attributes=True)
    id: int


class PolicyCreate(BaseModel):
    name: str
    description: str = ""
    enabled: bool = True
    priority: int = 100
    default_action: str = "allow"
    rules: list[PolicyRuleIn] = Field(default_factory=list)


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    description: str
    enabled: bool
    priority: int
    default_action: str
    rules: list[PolicyRuleOut]


class PolicyEvalRequest(BaseModel):
    user_uid: str = ""
    username: str = ""
    email: str = ""
    roles: list[str] = Field(default_factory=list)
    endpoint_id: str = ""
    src_ip: str = ""
    node_role: str = ""
    dst_ip: str = ""
    domain: str = ""
    category: str = ""
    port: int = 0
    protocol: str = ""
    country: str = ""
    asn: int = 0


class DecisionOut(BaseModel):
    action: str
    params: dict
    policy_id: str
    rule_id: int
    rule_name: str
    reason: str
    allowed: bool
