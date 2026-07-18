"""Thin wrapper around shelling out to data-plane tools (wg, ip, iptables).

Honours dry-run mode (log instead of execute) and gracefully degrades when the
tools or privileges are absent (development / simulation).
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from typing import Optional

log = logging.getLogger("fabric.agent.sys")


class System:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run

    def have(self, tool: str) -> bool:
        return shutil.which(tool) is not None

    def run(self, args: list[str], check: bool = False, capture: bool = False,
            input: Optional[str] = None) -> Optional[str]:
        cmd = " ".join(args)
        if self.dry_run or not self.have(args[0]):
            reason = "dry-run" if self.dry_run else f"'{args[0]}' not found"
            log.info("[%s] would run: %s", reason, cmd)
            return "" if capture else None
        try:
            res = subprocess.run(
                args, check=check, text=True, input=input,
                stdout=subprocess.PIPE if capture else None,
                stderr=subprocess.PIPE,
            )
            if capture:
                return res.stdout
            if res.returncode != 0 and res.stderr:
                log.warning("%s -> %s", cmd, res.stderr.strip())
            return None
        except subprocess.CalledProcessError as e:
            log.warning("command failed: %s (%s)", cmd, (e.stderr or "").strip())
            if check:
                raise
            return None
        except Exception as e:  # noqa: BLE001
            log.warning("command error: %s (%s)", cmd, e)
            return None
