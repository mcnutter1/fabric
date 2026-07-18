# Fabric — Network Connectivity Fabric Platform

Fabric is an endpoint-agnostic connectivity platform in the spirit of SASE / ZTNA:
a managed mesh of nodes that carries user and site traffic, applies identity- and
device-aware policy, inspects traffic (including TLS via a managed MITM CA),
filters DNS, and steers egress dynamically — all controlled from a single,
horizontally-scalable management layer.

```
                         ┌──────────────────────────────────────────┐
                         │            MANAGEMENT LAYER (AWS)          │
                         │  FastAPI · PKI · Policy Engine · Realtime  │
                         │      fabric.mcnutt.cloud  (HA + sync)      │
                         └───────────────┬──────────────────────────┘
                            control plane │ (mTLS API + WebSocket)
          ┌───────────────────────────────┼───────────────────────────────┐
          │                               │                               │
   ┌──────▼──────┐                 ┌──────▼──────┐                 ┌──────▼──────┐
   │  INGRESS    │◄── WireGuard ──►│   EGRESS    │◄── WireGuard ──►│  PRIVATE    │
   │  (clients)  │     fabric      │ (internet)  │     fabric      │ CONNECTOR   │
   └─────────────┘                 └─────────────┘                 └─────────────┘
        ▲   data plane flows over the node-to-node fabric, never the manager
   endpoints                                                       corp networks
```

## Core capabilities

- **Endpoint-agnostic access** — WireGuard first-class; L2TP/IPsec and OpenVPN
  supported through the same policy and PKI plane.
- **Fully-managed dumb nodes** — one install script + a pairing code. Everything
  else (config, updates, keys, routes) is pushed from the manager.
- **PKI** — offline-style Root CA → Intermediate CA → node/endpoint certs, plus a
  dedicated **MITM CA** for TLS inspection and a trusted root for endpoints.
- **Policy engine** — single engine keyed on **identity (user/role)** and
  **device/IP**, deciding allow / deny / inspect / steer / redirect.
- **Traffic inspection & classification** — TLS MITM (with override), L7
  classification, behavioural analytics.
- **DNS filtering + web monitoring** — capture, inspect, categorise, hijack /
  redirect / block, inject pages and messages.
- **Dynamic internet egress** — choose exit node/region by policy.
- **Self-healing fabric** — nodes mesh directly, health-monitor each other, and
  re-route around failures.
- **Real-time, visual management** — live traffic map, classification, ISP /
  country / category mapping, driven by WebSockets + jQuery.

## Repository layout

| Path | Purpose |
|------|---------|
| `management/` | The management layer — FastAPI app, PKI, policy engine, realtime hub, web UI. |
| `node-agent/` | The node agent that runs on every fabric node (ingress/egress/private). |
| `scripts/` | Turn-key `install-management.sh`, `install-node.sh`, `update.sh`. |
| `deploy/` | systemd units and deployment assets. |
| `docs/` | Architecture, protocol, and operations documentation. |

## Quick start (management, dev)

```bash
cd management
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # set FABRIC_* + auth app_id/app_secret
python -m app.seed              # create DB, root PKI, demo policy
uvicorn app.main:app --reload --host 0.0.0.0 --port 8080
# open http://localhost:8080
```

## Provision a node (production)

```bash
# on the manager: create the node, get a one-time pairing code (UI or API)
# on the fresh Ubuntu box:
curl -fsSL https://fabric.mcnutt.cloud/install/node.sh | sudo bash -s -- \
  --manager https://fabric.mcnutt.cloud --pair <PAIRING_CODE>
```

See [`docs/architecture.md`](docs/architecture.md) for the full design and
[`docs/operations.md`](docs/operations.md) for runbooks.
