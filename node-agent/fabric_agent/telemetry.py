"""Telemetry buffering — batches flow/DNS events and flushes to the manager."""
from __future__ import annotations

import logging
import threading
import time
from typing import Callable

log = logging.getLogger("fabric.agent.telemetry")


class TelemetryBuffer:
    def __init__(self, flush_flows: Callable[[list], object],
                 flush_dns: Callable[[list], object],
                 max_batch: int = 100):
        self._flows: list[dict] = []
        self._dns: list[dict] = []
        self._lock = threading.Lock()
        self._flush_flows = flush_flows
        self._flush_dns = flush_dns
        self.max_batch = max_batch

    def add_flow(self, flow: dict) -> None:
        with self._lock:
            self._flows.append(flow)
            drained = self._flows[: self.max_batch] if len(self._flows) >= self.max_batch else None
            if drained is not None:
                self._flows = self._flows[self.max_batch:]
        if drained:
            self._safe(self._flush_flows, drained)

    def add_dns(self, entry: dict) -> None:
        with self._lock:
            self._dns.append(entry)
            drained = self._dns[: self.max_batch] if len(self._dns) >= self.max_batch else None
            if drained is not None:
                self._dns = self._dns[self.max_batch:]
        if drained:
            self._safe(self._flush_dns, drained)

    def flush(self) -> None:
        with self._lock:
            flows, self._flows = self._flows, []
            dns, self._dns = self._dns, []
        if flows:
            self._safe(self._flush_flows, flows)
        if dns:
            self._safe(self._flush_dns, dns)

    @staticmethod
    def _safe(fn: Callable, batch: list) -> None:
        try:
            fn(batch)
        except Exception as e:  # noqa: BLE001
            log.warning("telemetry flush failed (%d dropped): %s", len(batch), e)
