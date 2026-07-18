"""PKI models: CA hierarchy and issued certificates."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import String, Integer, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..database import Base


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Certificate(Base):
    """A certificate in the PKI. CA private keys are stored encrypted at rest.

    Leaf/endpoint private keys are generally NOT stored (delivered once), except
    for CAs which the manager must retain to issue and sign.
    """
    __tablename__ = "certificates"

    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    kind: Mapped[str] = mapped_column(String(24), index=True)  # CertKind
    subject_cn: Mapped[str] = mapped_column(String(255), index=True)
    serial: Mapped[str] = mapped_column(String(64), index=True)

    issuer_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("certificates.id", ondelete="SET NULL"), nullable=True
    )

    cert_pem: Mapped[str] = mapped_column(Text)
    # encrypted private key (Fernet/AES) — only populated for CAs
    encrypted_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    not_before: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    not_after: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    revoked_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # optional binding to a node/endpoint
    subject_ref: Mapped[str] = mapped_column(String(64), default="")

    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    issuer: Mapped[Optional["Certificate"]] = relationship(remote_side="Certificate.id")
