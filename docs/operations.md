# Operations

Day-2 runbook for the Fabric platform: deploying, enrolling nodes, updating,
monitoring, and troubleshooting.

## Topology at a glance

```
                 ┌────────────────────────────┐
                 │   Management plane (AWS)    │
                 │  FastAPI + console + PKI    │  fabric.mcnutt.cloud
                 └──────────────┬─────────────┘
        mTLS / REST / WSS       │ pairing + config + telemetry
        ┌───────────────┬───────┴───────┬────────────────┐
   ┌────▼────┐     ┌────▼────┐     ┌─────▼─────┐    ┌─────▼─────┐
   │ egress  │     │ ingress │     │ connector │    │ connector │
   │ (AWS)   │     │(clients)│     │  (corp A) │    │  (corp B) │
   └─────────┘     └─────────┘     └───────────┘    └───────────┘
        └───────────────┴───── full-mesh WireGuard ─────┴────────┘
```

Initial deployment: 1 management + 1 egress + 1 ingress + 2 private connectors, in
a full WireGuard mesh (100.96.0.0/12 node fabric, 100.64.0.0/12 endpoint pool).

## Deploy the management plane

```bash
curl -fsSL https://raw.githubusercontent.com/mcnutter1/fabric/main/scripts/install-management.sh | sudo bash
sudoedit /etc/fabric/management.env      # set MCNUTT_APP_ID / APP_SECRET, keep generated secrets safe
sudo systemctl restart fabric-management
# front with TLS:
sudo cp /opt/fabric/deploy/nginx/fabric.conf /etc/nginx/sites-available/fabric.conf
sudo ln -s /etc/nginx/sites-available/fabric.conf /etc/nginx/sites-enabled/
sudo certbot --nginx -d fabric.mcnutt.cloud
```

Seed the starter fabric (creates nodes + default policy + bootstraps PKI):

```bash
cd /opt/fabric/management && sudo -u fabric .venv/bin/python -m app.seed
```

> Back up `FABRIC_PKI_PASSPHRASE`, `FABRIC_SESSION_SECRET`, and
> `/var/lib/fabric/fabric.db` together — the passphrase decrypts the CA keys.

## Enroll a node

1. In the console (**Nodes → Add node**) create the node with its role, or use a
   seeded one. Click **Pair** to mint a one-time code.
2. On the node host:

```bash
curl -fsSL https://fabric.mcnutt.cloud/install/node.sh | sudo bash -s -- \
     --manager https://fabric.mcnutt.cloud --pair XXXX-XXXX-XXXX
journalctl -u fabric-agent -f
```

The agent generates its WireGuard identity, enrolls, receives its token + certs +
config, programs the data plane, and starts streaming telemetry. The node flips to
**online** in the console and joins the mesh.

### Roles

| Role                | Programs                                              |
|---------------------|------------------------------------------------------|
| `egress`            | NAT/masquerade to internet; fetches MITM CA; inspection |
| `ingress`           | endpoint pool; DNS filtering resolver (100.64.0.1:53) |
| `private_connector` | forwarding + SNAT into advertised private CIDRs      |
| `relay`             | transit-only fabric hop for HA                        |

## Provision an endpoint (client)

**Endpoints → New endpoint** → choose user, OS, protocol (WireGuard / L2TP-IPSec /
OpenVPN) and ingress node. Download the config bundle (with QR for mobile) from the
config drawer. The bundle includes the tunnel config, install steps, and trust
bundle.

## Updating

```bash
sudo /opt/fabric/scripts/update.sh
```

Auto-detects management and/or agent services on the host, pulls `main`, refreshes
deps, and restarts only the active units. Safe to run repeatedly (no-op when up to
date). Roll back by `git -C /opt/fabric reset --hard <sha>` then re-run the
service restart.

## Monitoring & health

* **Console dashboard** — live nodes, flows/blocked (24h), category & country
  breakdowns, real-time event stream.
* **Map view** — geographic flow visualization + fabric topology with per-link
  latency/loss/handshake state.
* Heartbeats every ~15s update `last_seen`, node health, and pairwise link stats.
  A node with no heartbeat transitions online → degraded → offline; the mesh
  re-steers around it (self-healing).
* `GET /healthz` for liveness; `GET /api/v1/analytics/summary` for a metrics pull.

## HA & scaling

* Management is stateless except for the DB and the realtime bus. For HA: run
  multiple uvicorn instances behind the load balancer, point
  `FABRIC_DATABASE_URL` at Postgres, and set `FABRIC_REDIS_URL` so the realtime
  `EventHub` fans out across instances.
* Nodes are horizontally scalable per role; the orchestrator recomputes the mesh
  and per-node config whenever membership changes.

## Troubleshooting

| Symptom                                   | Check                                                        |
|-------------------------------------------|-------------------------------------------------------------|
| Node stuck `pending`                      | agent logs; pairing code expired? clock skew? manager reachable? |
| No peers / no handshake                   | `wg show fab0`; firewall on UDP 51820; correct public endpoint |
| DNS filtering not active                  | ingress role set? resolver bound to 100.64.0.1:53? logs      |
| Inspection not decrypting                 | egress role; MITM CA fetched (`/node/pki/mitm`); endpoint trusts MITM CA |
| Console shows "connecting…"               | WSS proxied? nginx `Upgrade`/`Connection` headers (see nginx conf) |
| `401` from `/node/*`                      | node token in `state.json`; token revoked in console?        |
| CA errors after restore                   | `FABRIC_PKI_PASSPHRASE` must match the one used at bootstrap |

Useful commands:

```bash
journalctl -u fabric-management -f
journalctl -u fabric-agent -f
wg show fab0
ip rule ; ip route show table 51820
sudo -u fabric /opt/fabric/management/.venv/bin/python -m app.seed   # idempotent re-seed
```

## Backups

Back up together, regularly:

* `/var/lib/fabric/fabric.db` (or your Postgres) — nodes, endpoints, policies, PKI.
* `/etc/fabric/management.env` — secrets, especially `FABRIC_PKI_PASSPHRASE`.

Restore = restore the DB, restore the env, restart `fabric-management`. Nodes
re-sync automatically on their next heartbeat.
