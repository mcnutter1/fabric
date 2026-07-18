"""Automatic Let's Encrypt certificate management for a node.

The manager tells each node (in its pushed config, under ``tls``) the FQDN that
was auto-provisioned for it in DNS and the ACME contact e-mail. This module
turns that into a trusted certificate using ``certbot`` in standalone mode
(HTTP-01 challenge), then links the issued material into ``<state>/tls`` so role
modules can serve TLS with a browser-trusted cert.

Renewal is handled by certbot's own systemd timer once the first cert exists.
Everything degrades gracefully: missing certbot, dry-run, or an unreachable
challenge port just logs and moves on.
"""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger("fabric.agent.acme")


class CertManager:
    def __init__(self, agent) -> None:
        self.agent = agent
        self.cfg = agent.cfg
        self.state = agent.state
        self.sys = agent.sys

    def apply(self, tls_cfg: dict | None) -> None:
        """Ensure a Let's Encrypt cert exists for the manager-assigned hostname."""
        tls_cfg = tls_cfg or {}
        if not tls_cfg.get("enabled"):
            return
        hostname = (tls_cfg.get("hostname") or "").strip()
        email = (tls_cfg.get("email") or "").strip()
        if not hostname:
            return

        live_dir = Path(f"/etc/letsencrypt/live/{hostname}")
        already = self.state.tls_hostname == hostname and live_dir.exists()
        if already:
            self._link(live_dir)
            return

        if self.cfg.dry_run:
            log.info("[dry-run] would obtain Let's Encrypt cert for %s (email=%s)",
                     hostname, email or "<none>")
            self.state.tls_hostname = hostname
            self.state.save(self.cfg.state_file)
            return

        if not self.sys.have("certbot"):
            log.warning("certbot not installed — cannot obtain cert for %s", hostname)
            return

        args = [
            "certbot", "certonly", "--standalone",
            "-n", "--agree-tos",
            "--http-01-port", str(self.cfg.acme_http_port),
            "-d", hostname,
            "--keep-until-expiring",
        ]
        if email:
            args += ["-m", email]
        else:
            args += ["--register-unsafely-without-email"]

        log.info("requesting Let's Encrypt certificate for %s", hostname)
        self.sys.run(args, check=False)

        if live_dir.exists():
            self._link(live_dir)
            self.state.tls_hostname = hostname
            self.state.save(self.cfg.state_file)
            log.info("certificate for %s installed", hostname)
        else:
            log.warning("certbot did not produce %s — check DNS + port %s reachability",
                        live_dir, self.cfg.acme_http_port)

    def _link(self, live_dir: Path) -> None:
        """Expose fullchain/privkey under <state>/tls for role modules."""
        try:
            self.cfg.tls_dir.mkdir(parents=True, exist_ok=True)
            for name in ("fullchain.pem", "privkey.pem"):
                src = live_dir / name
                dst = self.cfg.tls_dir / name
                if src.exists():
                    if dst.is_symlink() or dst.exists():
                        dst.unlink()
                    dst.symlink_to(src)
        except Exception as e:  # noqa: BLE001
            log.warning("could not link TLS material: %s", e)
