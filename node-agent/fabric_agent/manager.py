"""HTTP client for the Fabric management API (node-facing routes)."""
from __future__ import annotations

import logging
from typing import Optional

import httpx

log = logging.getLogger("fabric.agent.mgr")

API_PREFIX = "/api/v1"


class ManagerClient:
    def __init__(self, base_url: str, token: str = "", verify=True):
        self.base = base_url.rstrip("/")
        self.token = token
        self._client = httpx.Client(timeout=20.0, verify=verify)

    def close(self) -> None:
        self._client.close()

    def set_token(self, token: str) -> None:
        self.token = token

    # ------------------------------------------------------------ helpers
    def _url(self, path: str) -> str:
        return f"{self.base}{API_PREFIX}{path}"

    def _headers(self) -> dict:
        h = {"content-type": "application/json"}
        if self.token:
            h["authorization"] = f"Bearer {self.token}"
        return h

    def _post(self, path: str, json) -> dict:
        r = self._client.post(self._url(path), json=json, headers=self._headers())
        r.raise_for_status()
        return r.json() if r.content else {}

    def _get(self, path: str) -> dict:
        r = self._client.get(self._url(path), headers=self._headers())
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------ routes
    def enroll(self, code: str, wg_public_key: str, hostname: str,
               version: str, advertised_endpoint: str = "") -> dict:
        return self._post("/node/enroll", {
            "code": code,
            "wg_public_key": wg_public_key,
            "hostname": hostname,
            "version": version,
            "advertised_endpoint": advertised_endpoint,
        })

    def get_config(self) -> dict:
        return self._get("/node/config")

    def get_policy(self) -> dict:
        return self._get("/node/policy")

    def get_mitm_ca(self) -> Optional[dict]:
        try:
            return self._get("/node/pki/mitm")
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (403, 404):
                return None
            raise

    def heartbeat(self, version: str, health: dict, links: list[dict]) -> dict:
        return self._post("/node/heartbeat", {
            "version": version, "health": health, "links": links,
        })

    def report_flows(self, flows: list[dict]) -> dict:
        if not flows:
            return {"ok": True, "stored": 0}
        return self._post("/node/flows", flows)

    def report_dns(self, logs: list[dict]) -> dict:
        if not logs:
            return {"ok": True, "stored": 0}
        return self._post("/node/dns", logs)

    def report_endpoints(self, endpoints: list[dict]) -> dict:
        if not endpoints:
            return {"ok": True, "stored": 0}
        return self._post("/node/endpoints", endpoints)
