"""Agent configuration and persistent state.

Configuration precedence: CLI args > environment (FABRIC_AGENT_*) > defaults.
Runtime secrets (node token, keys, issued certs) live in a JSON state file under
the state dir (default /var/lib/fabric, or ./agent-state when not root).
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


def _default_state_dir() -> Path:
    # Prefer the system location when we can write there (root/systemd), else a
    # local dir for development.
    for candidate in ("/var/lib/fabric",):
        p = Path(candidate)
        try:
            p.mkdir(parents=True, exist_ok=True)
            test = p / ".w"
            test.write_text("1")
            test.unlink()
            return p
        except Exception:
            continue
    p = Path.cwd() / "agent-state"
    p.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class AgentConfig:
    manager_url: str = ""
    pairing_code: str = ""
    interface: str = "fab0"
    state_dir: Path = field(default_factory=_default_state_dir)
    heartbeat_interval: int = 15          # seconds
    config_poll_interval: int = 30        # seconds
    telemetry_flush_interval: int = 5     # seconds
    dns_listen: str = "100.64.0.1:53"     # fabric-side DNS resolver bind
    upstream_dns: str = "1.1.1.1"
    verify_tls: bool = True               # verify manager TLS (uses manager_ca)
    dry_run: bool = False                 # log data-plane commands instead of running
    simulate: bool = False                # emit synthetic telemetry (demo / no real traffic)
    advertised_endpoint: str = ""         # public ip:port override
    updater_path: str = "/opt/fabric/scripts/update.sh"  # invoked on manager update signal

    @classmethod
    def from_env(cls) -> "AgentConfig":
        e = os.environ.get
        cfg = cls(
            manager_url=e("FABRIC_AGENT_MANAGER", "") or e("FABRIC_MANAGER", ""),
            pairing_code=e("FABRIC_AGENT_PAIR", ""),
            interface=e("FABRIC_AGENT_IFACE", "fab0"),
            heartbeat_interval=int(e("FABRIC_AGENT_HEARTBEAT", "15")),
            config_poll_interval=int(e("FABRIC_AGENT_CONFIG_POLL", "30")),
            upstream_dns=e("FABRIC_AGENT_UPSTREAM_DNS", "1.1.1.1"),
            advertised_endpoint=e("FABRIC_AGENT_ENDPOINT", ""),
            verify_tls=e("FABRIC_AGENT_VERIFY_TLS", "1") != "0",
            dry_run=e("FABRIC_AGENT_DRY_RUN", "0") == "1",
            simulate=e("FABRIC_AGENT_SIMULATE", "0") == "1",
            updater_path=e("FABRIC_UPDATER", "/opt/fabric/scripts/update.sh"),
        )
        sd = e("FABRIC_AGENT_STATE_DIR", "")
        if sd:
            cfg.state_dir = Path(sd)
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
        return cfg

    # --- derived paths -------------------------------------------------
    @property
    def state_file(self) -> Path:
        return self.state_dir / "state.json"

    @property
    def wg_conf(self) -> Path:
        return self.state_dir / f"{self.interface}.conf"

    @property
    def manager_ca_file(self) -> Path:
        return self.state_dir / "manager-ca.pem"

    @property
    def node_cert_file(self) -> Path:
        return self.state_dir / "node.crt"

    @property
    def node_key_file(self) -> Path:
        return self.state_dir / "node.key"

    @property
    def mitm_ca_file(self) -> Path:
        return self.state_dir / "mitm-ca.pem"


@dataclass
class AgentState:
    node_id: str = ""
    node_token: str = ""
    fabric_addr: str = ""
    wg_listen_port: int = 51820
    roles: list = field(default_factory=list)
    wg_private_key: str = ""
    wg_public_key: str = ""
    last_config_version: str = ""
    enrolled: bool = False

    @classmethod
    def load(cls, path: Path) -> "AgentState":
        if path.exists():
            try:
                return cls(**json.loads(path.read_text()))
            except Exception:
                pass
        return cls()

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=2))
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
