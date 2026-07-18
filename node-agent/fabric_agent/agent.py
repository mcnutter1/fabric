"""Main agent orchestration loop.

Lifecycle:
 1. Ensure WireGuard identity + enroll (pairing) if not already enrolled.
 2. Persist token/certs; write manager CA for TLS verification.
 3. Pull config -> render + apply WireGuard, policy routing, role modules.
 4. Pull policy bundle -> program DNS filtering + local verdicts.
 5. Egress: fetch MITM CA -> ready TLS inspection; enable NAT.
 6. Loop: heartbeat (link stats) + periodic config/policy refresh + telemetry
    flush. Optionally emit simulated telemetry for visualisation.
"""
from __future__ import annotations

import json
import logging
import platform
import random
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import os
from typing import Optional

from . import __version__
from .classify import Classifier, sample_simulated_dns, sample_simulated_flow
from .config import AgentConfig, AgentState
from .certs import CertManager
from .dataplane import DataPlane
from .dns_filter import DNSResolver
from .manager import ManagerClient
from .policy import PolicyBundle
from .roles import build_roles
from .system import System
from .telemetry import TelemetryBuffer
from .wireguard import generate_keypair, render_wg_conf

log = logging.getLogger("fabric.agent")


class FabricAgent:
    def __init__(self, cfg: AgentConfig):
        self.cfg = cfg
        self.state = AgentState.load(cfg.state_file)
        self.sys = System(dry_run=cfg.dry_run)
        self.dp = DataPlane(cfg.interface, self.sys)
        self.classifier = Classifier(cfg.state_dir)
        self.manager: Optional[ManagerClient] = None
        self.telemetry: Optional[TelemetryBuffer] = None
        self.dns: Optional[DNSResolver] = None
        self.policy: Optional[PolicyBundle] = None
        self.inspector = None
        self.certs = CertManager(self)
        self.roles: list = []
        self._stop = threading.Event()
        self._pending_update_result: Optional[dict] = None

    # ------------------------------------------------------------ setup
    def _connect(self, token: str = "") -> ManagerClient:
        if not self.cfg.verify_tls:
            return ManagerClient(self.cfg.manager_url, token=token, verify=False)
        # Trust the system CA store (the management plane is fronted by nginx
        # with a public/Let's Encrypt cert) AND additively trust the fabric
        # manager CA if present, so self-signed management deployments also work.
        # The manager CA must never *replace* system trust, or a public cert on
        # the management endpoint fails to verify after enrollment.
        ctx = ssl.create_default_context()
        ca = self.cfg.manager_ca_file
        try:
            if ca.exists() and ca.stat().st_size > 0:
                ctx.load_verify_locations(str(ca))
        except Exception as e:  # noqa: BLE001
            log.warning("could not load manager CA %s: %s", ca, e)
        return ManagerClient(self.cfg.manager_url, token=token, verify=ctx)

    def _ensure_keys(self) -> None:
        if not self.state.wg_private_key:
            priv, pub = generate_keypair()
            self.state.wg_private_key = priv
            self.state.wg_public_key = pub
            self.state.save(self.cfg.state_file)
            log.info("generated WireGuard identity %s", pub[:16] + "...")

    def enroll(self) -> None:
        self._ensure_keys()
        client = self._connect()
        hostname = socket.gethostname()
        log.info("enrolling with %s using pairing code", self.cfg.manager_url)
        resp = client.enroll(
            code=self.cfg.pairing_code,
            wg_public_key=self.state.wg_public_key,
            hostname=hostname,
            version=__version__,
            advertised_endpoint=self.cfg.advertised_endpoint,
        )
        self.state.node_id = resp["node_id"]
        self.state.node_token = resp["node_token"]
        self.state.fabric_addr = resp["fabric_addr"]
        self.state.wg_listen_port = resp["wg_listen_port"]
        self.state.roles = resp.get("roles", [])
        self.state.enrolled = True
        self.state.save(self.cfg.state_file)

        # Persist issued PKI material + manager CA.
        _write(self.cfg.manager_ca_file, resp.get("manager_ca_pem", ""))
        _write(self.cfg.node_cert_file, resp.get("cert_pem", ""))
        _write(self.cfg.node_key_file, resp.get("key_pem", ""), secret=True)
        client.close()
        log.info("enrolled as node %s (%s) roles=%s fabric_addr=%s",
                 self.state.node_id, hostname, self.state.roles, self.state.fabric_addr)

    # ------------------------------------------------------------ config apply
    def apply_config(self) -> None:
        cfg = self.manager.get_config()
        version = cfg.get("version", "")
        if version and version == self.state.last_config_version:
            return
        log.info("applying config version %s (%d peers)", version, len(cfg.get("peers", [])))
        conf_text = render_wg_conf(self.state, cfg)
        _write(self.cfg.wg_conf, conf_text, secret=True)
        self.dp.apply_wireguard(self.cfg.wg_conf)
        self.dp.set_address(cfg.get("interface", {}).get("address", ""))
        self.dp.apply_routing(cfg.get("routing", {}))
        self._apply_roles(cfg)
        # Obtain/refresh a trusted Let's Encrypt cert for our assigned hostname.
        try:
            self.certs.apply(cfg.get("tls"))
        except Exception as e:  # noqa: BLE001
            log.warning("TLS provisioning failed: %s", e)
        self.state.last_config_version = version
        self.state.save(self.cfg.state_file)

    def _apply_roles(self, cfg: dict) -> None:
        """(Re)program every assigned role's data plane from the latest config."""
        if not self.roles:
            self.roles = build_roles(self, self.state.roles or cfg.get("roles", []))
            if self.roles:
                log.info("loaded roles: %s", [r.name for r in self.roles])
        for role in self.roles:
            try:
                role.setup(cfg)
            except Exception as e:  # noqa: BLE001
                log.warning("role %s setup failed: %s", role.name, e)

    def apply_policy(self) -> None:
        bundle = PolicyBundle(self.manager.get_policy())
        self.policy = bundle
        if self.dns:
            self.dns.set_policy(bundle)

    # ------------------------------------------------------------ heartbeat
    def _link_stats(self) -> list[dict]:
        """Build per-peer link stats from `wg show` keyed back to node_ids."""
        cfg = self.manager.get_config()
        # Only fabric-node peers carry a node_id; client endpoint peers don't and
        # report their own stats separately, so skip them here.
        pub_to_node = {p["public_key"]: p["node_id"] for p in cfg.get("peers", [])
                       if p.get("public_key") and p.get("node_id")}
        raw = self.dp.wg_link_stats()
        now = int(time.time())
        links = []
        for pub, s in raw.items():
            node_id = pub_to_node.get(pub)
            if not node_id:
                continue
            handshake_age = now - s["last_handshake"] if s["last_handshake"] else 9999
            links.append({
                "peer_id": node_id,
                "rx": s["rx"], "tx": s["tx"],
                "last_handshake_ok": s["last_handshake_ok"] and handshake_age < 180,
                "loss_pct": 0,
                "latency_ms": 0,
            })
        return links

    def heartbeat(self) -> None:
        health = {
            "version": __version__,
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "roles": self.state.roles,
            "ts": int(time.time()),
        }
        if self._pending_update_result:
            health["update_result"] = self._pending_update_result
        try:
            resp = self.manager.heartbeat(__version__, health, self._link_stats())
            if self._pending_update_result:
                self._clear_update_result()
                self._pending_update_result = None
            target = resp.get("target_version")
            if target and target != resp.get("config_version"):
                # Manager indicates config drift; refresh on next tick.
                self.state.last_config_version = ""
            if resp.get("update"):
                self._self_update()
        except Exception as e:  # noqa: BLE001
            log.warning("heartbeat failed: %s", e)

    def _load_update_result(self) -> Optional[dict]:
        """Read a self-update outcome left by the updater, to report once."""
        path = self.cfg.state_dir / "last-update.json"
        try:
            if path.exists():
                data = json.loads(path.read_text())
                if not data.get("reported"):
                    return data
        except Exception:  # noqa: BLE001
            return None
        return None

    def _clear_update_result(self) -> None:
        path = self.cfg.state_dir / "last-update.json"
        try:
            if path.exists():
                path.unlink()
        except Exception:  # noqa: BLE001
            pass

    def _self_update(self) -> None:
        """Run the in-package updater when the manager asks.

        The updater downloads the latest bundle and restarts fabric-agent. It
        MUST run outside this service's cgroup, otherwise `systemctl restart
        fabric-agent` (performed by the updater) would kill the updater
        mid-flight. We use `systemd-run --scope` for that isolation, falling
        back to a detached subprocess when systemd-run isn't available.

        Running through the package updater (not the raw shell script) means the
        outcome is written to state_dir/last-update.json, which the freshly
        restarted agent reports back to the manager on its next heartbeat.
        """
        if self.cfg.dry_run:
            log.info("[dry-run] would self-update")
            return
        agent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        py = sys.executable or "python3"
        update_cmd = [py, "-m", "fabric_agent", "update"]
        log.info("update requested by manager; launching self-update")
        try:
            if shutil.which("systemd-run"):
                subprocess.Popen(
                    ["systemd-run", "--scope", "--quiet",
                     "--collect", f"--setenv=PYTHONPATH={agent_dir}"] + update_cmd,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            else:
                env = {**os.environ, "PYTHONPATH": agent_dir}
                subprocess.Popen(update_cmd, cwd=agent_dir, env=env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True)
        except Exception as e:  # noqa: BLE001
            log.warning("self-update launch failed: %s", e)

    # ------------------------------------------------------------ simulation
    def _simulate_tick(self) -> None:
        for _ in range(random.randint(1, 5)):
            self.telemetry.add_flow({**sample_simulated_flow([]), "node_id": self.state.node_id,
                                     "egress_node_id": self.state.node_id})
        for _ in range(random.randint(0, 3)):
            self.telemetry.add_dns(sample_simulated_dns())

    # ------------------------------------------------------------ run loop
    def _initial_sync(self) -> None:
        """Pull config + policy once at startup, retrying instead of crashing.

        A manager outage or TLS verification error must not kill the service:
        we keep retrying with backoff so the heartbeat loop (and its self-update
        handling) still comes up and the node can recover on its own.
        """
        delay = 5
        while not self._stop.is_set():
            try:
                self.apply_config()
                self.apply_policy()
                return
            except Exception as e:  # noqa: BLE001
                log.warning("initial sync failed (%s); retrying in %ss", e, delay)
                self._stop.wait(delay)
                delay = min(delay * 2, 60)

    def run(self) -> None:
        if not self.cfg.manager_url:
            raise SystemExit("manager URL required (--manager or FABRIC_AGENT_MANAGER)")
        if not self.state.enrolled:
            if not self.cfg.pairing_code:
                raise SystemExit("not enrolled and no pairing code provided (--pair or FABRIC_AGENT_PAIR)")
            self.enroll()

        self.manager = self._connect(self.state.node_token)
        # If we just came up from a self-update, report the outcome once.
        self._pending_update_result = self._load_update_result()
        self.telemetry = TelemetryBuffer(
            flush_flows=lambda b: self.manager.report_flows(b),
            flush_dns=lambda b: self.manager.report_dns(b),
        )

        # Initial config/policy sync. Retry with backoff instead of letting a
        # transient manager outage or TLS error crash the process — otherwise
        # systemd crash-loops and we never reach the heartbeat/self-update loop.
        self._initial_sync()

        log.info("agent running (node=%s roles=%s sim=%s dry_run=%s)",
                 self.state.node_id, self.state.roles, self.cfg.simulate, self.cfg.dry_run)

        last_hb = last_cfg = last_flush = last_sim = last_tick = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_hb >= self.cfg.heartbeat_interval:
                self.heartbeat(); last_hb = now
            if now - last_cfg >= self.cfg.config_poll_interval:
                try:
                    self.apply_config(); self.apply_policy()
                except Exception as e:  # noqa: BLE001
                    log.warning("config/policy refresh failed: %s", e)
                last_cfg = now
            if now - last_tick >= 3:
                for role in self.roles:
                    try:
                        role.tick()
                    except Exception as e:  # noqa: BLE001
                        log.warning("role %s tick failed: %s", role.name, e)
                last_tick = now
            if now - last_flush >= self.cfg.telemetry_flush_interval:
                self.telemetry.flush(); last_flush = now
            if self.cfg.simulate and now - last_sim >= 2:
                self._simulate_tick(); last_sim = now
            self._stop.wait(1.0)

        self.telemetry.flush()
        for role in self.roles:
            try:
                role.teardown()
            except Exception as e:  # noqa: BLE001
                log.warning("role %s teardown failed: %s", role.name, e)
        if self.dns:
            self.dns.stop()
        self.manager.close()

    def stop(self) -> None:
        self._stop.set()


def _write(path, text: str, secret: bool = False) -> None:
    if not text:
        return
    path.write_text(text)
    if secret:
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
