"""TLS inspection (MITM) support for egress nodes.

The manager provisions the intermediate MITM CA (cert + private key) to egress
nodes via /node/pki/mitm. This module loads that CA and mints short-lived leaf
certificates on demand for observed SNI hostnames, enabling a TLS-terminating
proxy to inspect and re-classify traffic. Endpoints trust the MITM CA (delivered
in their trust bundle), so inspected sessions validate cleanly.

The actual bytestream proxy is intentionally out of scope here; this provides the
certificate authority machinery + a hook the proxy calls per connection.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import Optional

log = logging.getLogger("fabric.agent.inspect")


class TLSInspector:
    def __init__(self, ca_cert_pem: str, ca_key_pem: str):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        self._x509 = x509
        self._ca_cert = x509.load_pem_x509_certificate(ca_cert_pem.encode())
        self._ca_key = serialization.load_pem_private_key(ca_key_pem.encode(), password=None)
        self._cache: dict[str, tuple] = {}

    def leaf_for(self, hostname: str, ttl_hours: int = 24) -> tuple[str, str]:
        """Return (cert_pem, key_pem) for `hostname`, minting + caching as needed."""
        if hostname in self._cache:
            return self._cache[hostname]
        pair = self._mint(hostname, ttl_hours)
        self._cache[hostname] = pair
        return pair

    def _mint(self, hostname: str, ttl_hours: int) -> tuple[str, str]:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        x509 = self._x509

        key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc)
        subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, hostname)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(hours=ttl_hours))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
        )
        cert = builder.sign(self._ca_key, hashes.SHA256())
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        return cert_pem, key_pem


def load_inspector(mitm: Optional[dict]) -> Optional[TLSInspector]:
    if not mitm or not mitm.get("ca_cert_pem") or not mitm.get("ca_key_pem"):
        return None
    try:
        insp = TLSInspector(mitm["ca_cert_pem"], mitm["ca_key_pem"])
        log.info("TLS inspection ready (MITM CA loaded)")
        return insp
    except Exception as e:  # noqa: BLE001
        log.warning("failed to initialise TLS inspector: %s", e)
        return None
