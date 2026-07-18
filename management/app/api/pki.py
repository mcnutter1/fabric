"""PKI routes — CA status, trusted-root download, and leaf issuance."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import Principal, require_admin, get_current_user
from ..database import get_db
from ..models import Certificate
from ..models.enums import CertKind
from ..services.pki import PKIService
from ..util import audit

router = APIRouter(prefix="/pki", tags=["pki"])


@router.get("/status")
def pki_status(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    out = {}
    for kind in (CertKind.root_ca, CertKind.infra_ca, CertKind.endpoint_ca, CertKind.mitm_ca):
        c = db.scalar(select(Certificate).where(Certificate.kind == kind.value))
        out[kind.value] = None if not c else {
            "id": c.id, "subject_cn": c.subject_cn, "serial": c.serial,
            "not_before": c.not_before, "not_after": c.not_after,
        }
    issued = db.scalar(select(Certificate).where(Certificate.kind.in_(
        [CertKind.node.value, CertKind.endpoint.value, CertKind.leaf.value]
    )))
    out["initialised"] = bool(out[CertKind.root_ca.value])
    return out


@router.post("/bootstrap")
def bootstrap(db: Session = Depends(get_db), admin: Principal = Depends(require_admin)):
    cas = PKIService(db).bootstrap()
    audit(db, actor=admin.email, actor_type="user", action="pki.bootstrap", target="ca")
    return {k: {"id": v.id, "subject_cn": v.subject_cn} for k, v in cas.items()}


@router.get("/trusted-root.pem", response_class=PlainTextResponse)
def trusted_root(db: Session = Depends(get_db)):
    """Public bundle endpoints install to trust the fabric (root + endpoint + MITM CA)."""
    pem = PKIService(db).trusted_root_bundle()
    return PlainTextResponse(pem, media_type="application/x-pem-file",
                             headers={"Content-Disposition": "attachment; filename=fabric-root.pem"})


@router.get("/certificates")
def list_certs(db: Session = Depends(get_db), _: Principal = Depends(require_admin)):
    certs = db.scalars(select(Certificate).order_by(Certificate.created_at.desc()))
    return [
        {"id": c.id, "kind": c.kind, "subject_cn": c.subject_cn, "serial": c.serial,
         "not_after": c.not_after, "revoked": c.revoked, "subject_ref": c.subject_ref}
        for c in certs
    ]
