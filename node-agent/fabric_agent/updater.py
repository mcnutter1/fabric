"""Self-contained node updater.

`python3 -m fabric_agent update` pulls the latest agent bundle from the
management plane over HTTPS and reinstalls it in place, then restarts the
service — no external curl/bash required. The manager URL and TLS settings are
read from the same agent configuration/environment the running agent uses.

The result of the update (ok/failed + message) is written to
``<state_dir>/last-update.json`` so the freshly-restarted agent can report the
outcome back to the manager on its next heartbeat.
"""
from __future__ import annotations

import io
import json
import logging
import os
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

import httpx

from . import __version__
from .config import AgentConfig

log = logging.getLogger("fabric.agent.update")


def _prefix() -> Path:
    """Installation root (contains node-agent/, deploy/, scripts/)."""
    env = os.environ.get("FABRIC_PREFIX")
    if env:
        return Path(env)
    # .../<prefix>/node-agent/fabric_agent/updater.py -> <prefix>
    return Path(__file__).resolve().parent.parent.parent


def _tls_verify(cfg: AgentConfig):
    """Mirror the agent's TLS trust: system CAs plus the manager CA if present."""
    if not cfg.verify_tls:
        return False
    ctx = ssl.create_default_context()
    ca = cfg.manager_ca_file
    try:
        if ca.exists() and ca.stat().st_size > 0:
            ctx.load_verify_locations(str(ca))
    except Exception as e:  # noqa: BLE001
        log.warning("could not load manager CA %s: %s", ca, e)
    return ctx


def _pip_supports_break_system() -> bool:
    try:
        out = subprocess.run([sys.executable, "-m", "pip", "install", "--help"],
                             capture_output=True, text=True, timeout=30)
        return "break-system-packages" in (out.stdout or "")
    except Exception:  # noqa: BLE001
        return False


def _write_result(cfg: AgentConfig, ok: bool, message: str, to_version: str = "") -> None:
    try:
        path = cfg.state_dir / "last-update.json"
        path.write_text(json.dumps({
            "ok": ok,
            "ts": int(time.time()),
            "message": message,
            "version": to_version or __version__,
            "reported": False,
        }))
    except Exception as e:  # noqa: BLE001
        log.warning("could not write update result: %s", e)


def _safe_extract(tf: tarfile.TarFile, dest: Path) -> None:
    """Extract guarding against path traversal (CVE-2007-4559 style)."""
    dest = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        if target != dest and not str(target).startswith(str(dest) + os.sep):
            raise RuntimeError(f"unsafe path in bundle: {member.name}")
    tf.extractall(dest)


def _copy_tree(src: Path, dst: Path) -> None:
    for child in src.iterdir():
        target = dst / child.name
        if child.is_dir():
            shutil.copytree(child, target, dirs_exist_ok=True)
        else:
            shutil.copy2(child, target)


def _install_unit(prefix: Path) -> None:
    unit = prefix / "deploy" / "systemd" / "fabric-agent.service"
    if not unit.exists():
        return
    try:
        dst = Path("/etc/systemd/system/fabric-agent.service")
        shutil.copyfile(unit, dst)
        os.chmod(dst, 0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=False)
    except Exception as e:  # noqa: BLE001
        log.warning("could not reinstall systemd unit: %s", e)


def _pip_install(prefix: Path) -> None:
    req = prefix / "node-agent" / "requirements.txt"
    if not req.exists():
        return
    cmd = [sys.executable, "-m", "pip", "install", "-q"]
    if _pip_supports_break_system():
        cmd.append("--break-system-packages")
    cmd += ["-r", str(req)]
    subprocess.run(cmd, check=False)


def _restart() -> None:
    try:
        subprocess.Popen(["systemctl", "restart", "fabric-agent.service"],
                         start_new_session=True)
    except Exception as e:  # noqa: BLE001
        log.warning("could not restart service: %s", e)


def run_update(cfg: AgentConfig, restart: bool = True) -> int:
    prefix = _prefix()
    bundle_url = os.environ.get("FABRIC_BUNDLE_URL") or (
        cfg.manager_url.rstrip("/") + "/install/node-agent.tar.gz" if cfg.manager_url else "")
    if not bundle_url:
        log.error("no manager URL configured (set FABRIC_AGENT_MANAGER or --manager)")
        return 2

    log.info("updating %s from %s", prefix, bundle_url)
    try:
        with httpx.Client(timeout=60, verify=_tls_verify(cfg), follow_redirects=True) as c:
            resp = c.get(bundle_url)
            resp.raise_for_status()
            data = resp.content
    except Exception as e:  # noqa: BLE001
        log.error("bundle download failed: %s", e)
        _write_result(cfg, False, f"download failed: {e}")
        return 1
    if not data:
        log.error("downloaded bundle is empty")
        _write_result(cfg, False, "empty bundle")
        return 1

    stage = Path(tempfile.mkdtemp(prefix="fabric-bundle."))
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            _safe_extract(tf, stage)
        if not (stage / "node-agent" / "requirements.txt").exists():
            log.error("bundle missing node-agent payload")
            _write_result(cfg, False, "invalid bundle")
            return 1
        prefix.mkdir(parents=True, exist_ok=True)
        _copy_tree(stage, prefix)
        _install_unit(prefix)
        _pip_install(prefix)
    except Exception as e:  # noqa: BLE001
        log.error("update failed: %s", e)
        _write_result(cfg, False, f"apply failed: {e}")
        return 1
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    _write_result(cfg, True, "updated", __version__)
    log.info("update applied to %s (version %s)", prefix, __version__)
    if restart:
        log.info("restarting fabric-agent")
        _restart()
    return 0
