"""CLI entrypoint: `python -m fabric_agent`."""
from __future__ import annotations

import argparse
import logging
import signal
import sys

from . import __version__
from .agent import FabricAgent
from .config import AgentConfig


def _parse_args(argv=None) -> AgentConfig:
    cfg = AgentConfig.from_env()
    p = argparse.ArgumentParser("fabric-agent", description="Fabric node data-plane agent")
    p.add_argument("--manager", default=cfg.manager_url, help="management base URL (https://fabric.mcnutt.cloud)")
    p.add_argument("--pair", default=cfg.pairing_code, help="one-time pairing code")
    p.add_argument("--interface", default=cfg.interface, help="WireGuard interface name")
    p.add_argument("--state-dir", default=str(cfg.state_dir), help="state directory")
    p.add_argument("--endpoint", default=cfg.advertised_endpoint, help="advertised public ip:port")
    p.add_argument("--upstream-dns", default=cfg.upstream_dns)
    p.add_argument("--heartbeat", type=int, default=cfg.heartbeat_interval)
    p.add_argument("--no-verify-tls", action="store_true", help="disable manager TLS verification")
    p.add_argument("--dry-run", action="store_true", help="log data-plane commands instead of executing")
    p.add_argument("--simulate", action="store_true", help="emit synthetic telemetry for visualisation")
    p.add_argument("--verbose", "-v", action="store_true")
    p.add_argument("--version", action="version", version=f"fabric-agent {__version__}")
    a = p.parse_args(argv)

    from pathlib import Path
    cfg.manager_url = a.manager
    cfg.pairing_code = a.pair
    cfg.interface = a.interface
    cfg.state_dir = Path(a.state_dir)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    cfg.advertised_endpoint = a.endpoint
    cfg.upstream_dns = a.upstream_dns
    cfg.heartbeat_interval = a.heartbeat
    if a.no_verify_tls:
        cfg.verify_tls = False
    if a.dry_run:
        cfg.dry_run = True
    if a.simulate:
        cfg.simulate = True
    cfg._verbose = a.verbose  # type: ignore[attr-defined]
    return cfg


def main(argv=None) -> int:
    cfg = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if getattr(cfg, "_verbose", False) else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s: %(message)s",
    )
    agent = FabricAgent(cfg)

    def _sig(_signum, _frame):
        logging.getLogger("fabric.agent").info("shutting down")
        agent.stop()

    signal.signal(signal.SIGINT, _sig)
    signal.signal(signal.SIGTERM, _sig)
    try:
        agent.run()
    except SystemExit as e:
        print(str(e), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
