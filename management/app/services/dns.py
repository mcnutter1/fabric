"""Route53 DNS automation for node hostnames.

When a node comes online the orchestrator gives it a stable FQDN under
``settings.node_base_domain`` and points an A record at the public IP the node
registered with. That hostname is then used by the node to obtain a trusted
Let's Encrypt certificate.

Everything degrades gracefully: if boto3 is missing or Route53 isn't configured,
calls return ``False`` and the caller simply skips DNS/TLS automation.
"""
from __future__ import annotations

import logging
import re

from ..config import settings

log = logging.getLogger("fabric.dns")

_SLUG_RE = re.compile(r"[^a-z0-9-]+")


def node_fqdn(name: str) -> str:
    """Derive a DNS-safe FQDN for a node under the configured base domain."""
    if not settings.node_base_domain:
        return ""
    label = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-") or "node"
    return f"{label}.{settings.node_base_domain}"


class Route53Service:
    def __init__(self) -> None:
        self._client = None

    @property
    def enabled(self) -> bool:
        return settings.node_dns_enabled

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3  # type: ignore
        except Exception:  # noqa: BLE001
            log.warning("boto3 not installed — Route53 automation disabled")
            return None
        try:
            self._client = boto3.client("route53", region_name=settings.aws_region)
        except Exception as e:  # noqa: BLE001
            log.warning("could not create Route53 client: %s", e)
            return None
        return self._client

    def upsert_a(self, fqdn: str, ip: str, ttl: int = 60) -> bool:
        """Create/replace an A record ``fqdn -> ip``. Returns True on success."""
        if not (self.enabled and fqdn and ip):
            return False
        client = self._get_client()
        if client is None:
            return False
        try:
            client.change_resource_record_sets(
                HostedZoneId=settings.route53_zone_id,
                ChangeBatch={
                    "Comment": "fabric node auto-provision",
                    "Changes": [{
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": fqdn,
                            "Type": "A",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }],
                },
            )
            log.info("route53 UPSERT %s -> %s", fqdn, ip)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("route53 upsert failed for %s: %s", fqdn, e)
            return False

    def delete_a(self, fqdn: str, ip: str, ttl: int = 60) -> bool:
        """Best-effort delete of an A record (used when a node is removed)."""
        if not (self.enabled and fqdn and ip):
            return False
        client = self._get_client()
        if client is None:
            return False
        try:
            client.change_resource_record_sets(
                HostedZoneId=settings.route53_zone_id,
                ChangeBatch={
                    "Comment": "fabric node deprovision",
                    "Changes": [{
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": fqdn,
                            "Type": "A",
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": ip}],
                        },
                    }],
                },
            )
            log.info("route53 DELETE %s -> %s", fqdn, ip)
            return True
        except Exception as e:  # noqa: BLE001
            log.warning("route53 delete failed for %s: %s", fqdn, e)
            return False
