"""PKI service — Root CA, intermediate CAs (infra/endpoint/MITM), and leaf issuance.

Hierarchy:

    Fabric Root CA
      ├── Fabric Infrastructure CA   -> node identity certs (mTLS control plane)
      ├── Fabric Endpoint CA         -> endpoint/client certs + trusted root
      └── Fabric Inspection (MITM) CA-> on-the-fly TLS leaves for inspection

CA private keys are stored encrypted at rest (Fernet key derived from the
configured PKI passphrase). Leaf private keys are returned to the caller once
and are not persisted (except CAs, which the manager must retain to sign).
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import uuid
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import Certificate
from ..models.enums import CertKind


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.pki_passphrase.encode()).digest())
    return Fernet(key)


def _encrypt_key(pem: bytes) -> str:
    return _fernet().encrypt(pem).decode()


def _decrypt_key(token: str) -> bytes:
    return _fernet().decrypt(token.encode())


def _serial() -> int:
    return x509.random_serial_number()


@dataclass
class IssuedCert:
    cert_pem: str
    key_pem: Optional[str]   # None when the private key was not generated here
    chain_pem: str           # issuer chain up to (but excluding) root
    record_id: str


class PKIService:
    def __init__(self, db: Session):
        self.db = db

    # ------------------------------------------------------------------ CA bootstrap
    def ensure_root(self) -> Certificate:
        existing = self.db.scalar(select(Certificate).where(Certificate.kind == CertKind.root_ca.value))
        if existing:
            return existing
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fabric"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Fabric Root CA"),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(_serial())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=2), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        return self._persist(CertKind.root_ca, cert, key, issuer_id=None, subject_ref="root")

    def ensure_intermediate(self, kind: CertKind, cn: str) -> Certificate:
        existing = self.db.scalar(select(Certificate).where(Certificate.kind == kind.value))
        if existing:
            return existing
        root = self.ensure_root()
        root_key = self._load_key(root)
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Fabric"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(x509.load_pem_x509_certificate(root.cert_pem.encode()).subject)
            .public_key(key.public_key())
            .serial_number(_serial())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                key_encipherment=False, content_commitment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(root_key, hashes.SHA256())
        )
        return self._persist(kind, cert, key, issuer_id=root.id, subject_ref=kind.value)

    def bootstrap(self) -> dict[str, Certificate]:
        """Create the full CA hierarchy if it does not yet exist."""
        root = self.ensure_root()
        infra = self.ensure_intermediate(CertKind.infra_ca, "Fabric Infrastructure CA")
        endpoint = self.ensure_intermediate(CertKind.endpoint_ca, "Fabric Endpoint CA")
        mitm = self.ensure_intermediate(CertKind.mitm_ca, "Fabric Inspection CA")
        return {"root": root, "infra": infra, "endpoint": endpoint, "mitm": mitm}

    # ------------------------------------------------------------------ leaf issuance
    def issue_node_cert(self, node_id: str, cn: str, sans: Optional[list[str]] = None) -> IssuedCert:
        ca = self.ensure_intermediate(CertKind.infra_ca, "Fabric Infrastructure CA")
        return self._issue_leaf(
            ca, CertKind.node, cn, subject_ref=node_id, sans=sans or [],
            client_auth=True, server_auth=True, days=825,
        )

    def issue_endpoint_cert(self, endpoint_id: str, cn: str, sans: Optional[list[str]] = None) -> IssuedCert:
        ca = self.ensure_intermediate(CertKind.endpoint_ca, "Fabric Endpoint CA")
        return self._issue_leaf(
            ca, CertKind.endpoint, cn, subject_ref=endpoint_id, sans=sans or [],
            client_auth=True, server_auth=False, days=825,
        )

    def issue_mitm_leaf(self, hostname: str) -> IssuedCert:
        """Mint an on-the-fly leaf for TLS inspection of a given hostname.

        In production this is delegated to egress nodes (which hold the MITM CA
        key material) so leaves are minted at line rate; this method is used for
        testing and for the manager-side inspection preview.
        """
        ca = self.ensure_intermediate(CertKind.mitm_ca, "Fabric Inspection CA")
        return self._issue_leaf(
            ca, CertKind.leaf, hostname, subject_ref=hostname, sans=[hostname],
            client_auth=False, server_auth=True, days=30,
        )

    def _issue_leaf(self, ca: Certificate, kind: CertKind, cn: str, *, subject_ref: str,
                    sans: list[str], client_auth: bool, server_auth: bool, days: int) -> IssuedCert:
        ca_cert = x509.load_pem_x509_certificate(ca.cert_pem.encode())
        ca_key = self._load_key(ca)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

        san_list: list[x509.GeneralName] = []
        for s in sans or [cn]:
            try:
                san_list.append(x509.IPAddress(_ip(s)))
            except ValueError:
                san_list.append(x509.DNSName(s))

        eku = []
        if server_auth:
            eku.append(ExtendedKeyUsageOID.SERVER_AUTH)
        if client_auth:
            eku.append(ExtendedKeyUsageOID.CLIENT_AUTH)

        now = dt.datetime.now(dt.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(_serial())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        )
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
        cert = builder.sign(ca_key, hashes.SHA256())

        # Persist the public cert (not the leaf private key).
        record = self._persist(kind, cert, key=None, issuer_id=ca.id, subject_ref=subject_ref)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        chain_pem = self.chain_pem(ca)
        return IssuedCert(
            cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            key_pem=key_pem,
            chain_pem=chain_pem,
            record_id=record.id,
        )

    # ------------------------------------------------------------------ helpers
    def chain_pem(self, ca: Certificate) -> str:
        """Return the issuer chain PEM (intermediate + root)."""
        parts = [ca.cert_pem]
        cur = ca
        while cur.issuer_id:
            parent = self.db.get(Certificate, cur.issuer_id)
            if not parent:
                break
            parts.append(parent.cert_pem)
            cur = parent
        return "\n".join(p.strip() for p in parts) + "\n"

    def ca_pem(self, kind: CertKind) -> Optional[str]:
        c = self.db.scalar(select(Certificate).where(Certificate.kind == kind.value))
        return c.cert_pem if c else None

    def trusted_root_bundle(self) -> str:
        """The bundle endpoints install to trust the fabric (root + endpoint + MITM CA)."""
        parts = []
        for kind in (CertKind.root_ca, CertKind.endpoint_ca, CertKind.mitm_ca):
            pem = self.ca_pem(kind)
            if pem:
                parts.append(pem.strip())
        return "\n".join(parts) + "\n"

    def _persist(self, kind: CertKind, cert: x509.Certificate, key, *,
                 issuer_id: Optional[str], subject_ref: str) -> Certificate:
        rec = Certificate(
            id=uuid.uuid4().hex[:32],
            kind=kind.value,
            subject_cn=cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            serial=format(cert.serial_number, "x"),
            issuer_id=issuer_id,
            cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            encrypted_key=(
                _encrypt_key(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )) if key is not None else None
            ),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            subject_ref=subject_ref,
        )
        self.db.add(rec)
        self.db.commit()
        self.db.refresh(rec)
        return rec

    def _load_key(self, record: Certificate):
        if not record.encrypted_key:
            raise ValueError(f"certificate {record.id} has no private key")
        return serialization.load_pem_private_key(_decrypt_key(record.encrypted_key), password=None)


def _ip(value: str):
    import ipaddress
    return ipaddress.ip_address(value)
