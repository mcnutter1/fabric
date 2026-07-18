# Fabric Node Agent

A **dumb** data-plane agent. All intelligence — topology, policy, PKI — lives in
the [management plane](../management). The agent pairs, pulls its config, programs
the local data plane, and streams telemetry back.

## What it does

1. **Enroll** — generate a WireGuard identity, redeem a one-time pairing code
   (`/node/enroll`), persist the returned node token + certs + manager CA.
2. **Apply config** — render `fab0.conf`, bring up the WireGuard mesh
   (`Table = off`), and program policy routing (internet → egress peer, private
   CIDR → connector, endpoint pool → ingress).
3. **Roles** — egress: NAT + fetch MITM CA + TLS inspection; ingress: DNS
   filtering resolver; connector: forward/SNAT into private CIDRs.
4. **Enforce policy** — evaluate the compiled policy bundle locally (first-match
   wins) for DNS and per-flow verdicts.
5. **Report** — heartbeat with per-peer link stats; batch flow/DNS telemetry to
   the manager (which fans it out to the live console).

## Run

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt

python -m fabric_agent \
  --manager https://fabric.mcnutt.cloud \
  --pair XXXX-XXXX-XXXX
```

Production installs run under systemd via
[`scripts/install-node.sh`](../scripts/install-node.sh).

### Useful flags

| Flag / env                       | Purpose                                        |
|----------------------------------|------------------------------------------------|
| `--manager` / `FABRIC_AGENT_MANAGER` | management base URL                        |
| `--pair` / `FABRIC_AGENT_PAIR`   | one-time pairing code (first run only)          |
| `--interface` (`fab0`)           | WireGuard interface name                        |
| `--state-dir` (`/var/lib/fabric`)| where token/keys/certs are persisted            |
| `--endpoint`                     | advertised public `ip:port`                     |
| `--dry-run`                      | log data-plane commands instead of running them |
| `--simulate`                     | emit synthetic classified telemetry (demo)      |
| `--no-verify-tls`                | disable manager TLS verification (dev)          |

`--dry-run --simulate` is handy for local demos: it enrolls, prints the `wg`/`ip`
commands it *would* run, and streams realistic flows/DNS so the console lights up
without a real data plane.

## Layout

```
fabric_agent/
  agent.py       orchestration loop (enroll → apply → heartbeat/telemetry)
  manager.py     HTTP client for /node/* routes
  wireguard.py   X25519 keygen + wg-quick config rendering
  dataplane.py   ip/wg/iptables programming + wg stats parsing
  dns_filter.py  DNS interception + category/domain filtering (dnslib)
  inspect.py     MITM leaf minting from the inspection CA
  policy.py      local first-match-wins policy evaluation
  classify.py    domain→category, IP→geo/ASN/ISP (+ simulation)
  telemetry.py   batched flow/DNS reporting
  config.py      config + persistent state
  system.py      safe shell wrapper (dry-run aware)
```
