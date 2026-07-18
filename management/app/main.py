"""FastAPI application factory."""
from __future__ import annotations

import contextlib
import io
import tarfile
import time
from pathlib import Path

from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .config import settings
from .database import init_db, SessionLocal
from .api import api_router, ws
from .auth import get_current_user, Principal
from .realtime import hub

BASE_DIR = Path(__file__).resolve().parent
WEB_DIR = BASE_DIR / "web"
REPO_ROOT = BASE_DIR.parent.parent
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

# Directories shipped to a node in the self-contained install bundle.
_BUNDLE_DIRS = ("node-agent", "deploy", "scripts")
# Simple in-process cache so we don't re-tar on every poll.
_bundle_cache: dict = {"data": None, "built": 0.0}


def _build_node_bundle() -> bytes:
    """Tar+gzip the node-side code straight from this checkout so a node can
    install everything from the management plane without touching GitHub."""
    now = time.time()
    if _bundle_cache["data"] is not None and (now - _bundle_cache["built"]) < 30:
        return _bundle_cache["data"]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name in _BUNDLE_DIRS:
            path = REPO_ROOT / name
            if path.exists():
                tar.add(str(path), arcname=name, filter=_bundle_filter)
    data = buf.getvalue()
    _bundle_cache["data"] = data
    _bundle_cache["built"] = now
    return data


def _bundle_filter(info: "tarfile.TarInfo"):
    # Skip noise the node never needs.
    parts = info.name.split("/")
    skip = {"__pycache__", ".venv", ".git", "node_modules", ".pytest_cache", ".mypy_cache"}
    if any(p in skip for p in parts) or info.name.endswith((".pyc", ".pyo")):
        return None
    return info


_PROVISION_INVALID = (
    "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Fabric</title></head><body style='font-family:-apple-system,sans-serif;background:#0b1220;"
    "color:#e7eefb;text-align:center;padding:60px 20px'><h2>Link expired or invalid</h2>"
    "<p style='color:#9fb2d0'>Ask your administrator for a fresh provisioning link.</p></body></html>"
)


def _human_expiry(exp) -> str:
    import datetime as _dt
    if not exp:
        return "soon"
    delta = exp - _dt.datetime.now(_dt.timezone.utc)
    secs = int(delta.total_seconds())
    if secs <= 0:
        return "now"
    hours = secs // 3600
    if hours >= 24:
        return f"in {hours // 24} day(s)"
    if hours >= 1:
        return f"in {hours} hour(s)"
    return f"in {max(1, secs // 60)} minute(s)"


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    await hub.start()
    yield
    await hub.stop()


def create_app() -> FastAPI:
    app = FastAPI(title="Fabric Management Layer", version="1.0.0", lifespan=lifespan)

    # REST API
    app.include_router(api_router, prefix="/api/v1")
    # WebSockets
    app.include_router(ws.router)

    # Static assets
    static_dir = WEB_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # ---- Node install script (served for the one-liner installer) ----
    @app.get("/install/node.sh", response_class=PlainTextResponse)
    async def install_node_sh():
        script = REPO_ROOT / "scripts" / "install-node.sh"
        if script.exists():
            return PlainTextResponse(script.read_text(), media_type="text/x-shellscript")
        return PlainTextResponse("#!/usr/bin/env bash\necho 'installer unavailable'\n", status_code=404)

    # ---- Self-contained node bundle (agent code, served from the mgmt plane) ----
    @app.get("/install/node-agent.tar.gz")
    async def install_node_bundle():
        data = _build_node_bundle()
        return Response(
            content=data,
            media_type="application/gzip",
            headers={"Content-Disposition": "attachment; filename=fabric-node-agent.tar.gz"},
        )

    # ---- One-line bootstrap: wget -qO- <url>/i/<code> | sudo bash ----
    @app.get("/i/{code}", response_class=PlainTextResponse)
    async def bootstrap_installer(code: str):
        from .models import PairingCode
        db = SessionLocal()
        try:
            pairing = db.query(PairingCode).filter(PairingCode.code == code).first()
            if not pairing or not pairing.is_valid:
                return PlainTextResponse(
                    "#!/usr/bin/env bash\necho 'fabric: invalid or expired pairing code' >&2\nexit 1\n",
                    status_code=404, media_type="text/x-shellscript",
                )
        finally:
            db.close()
        base = settings.public_url.rstrip("/")
        script = "\n".join([
            "#!/usr/bin/env bash",
            "# Fabric node bootstrap — downloads the agent from the management",
            "# plane and enrols this host automatically. Run as root:",
            f"#   wget -qO- {base}/i/{code} | sudo bash",
            "set -euo pipefail",
            f'export FABRIC_AGENT_MANAGER="{base}"',
            f'export FABRIC_AGENT_PAIR="{code}"',
            f'export FABRIC_BUNDLE_URL="{base}/install/node-agent.tar.gz"',
            'if command -v curl >/dev/null 2>&1; then',
            f'  curl -fsSL "{base}/install/node.sh" | bash',
            'else',
            f'  wget -qO- "{base}/install/node.sh" | bash',
            'fi',
            "",
        ])
        return PlainTextResponse(script, media_type="text/x-shellscript")

    # ---- Public endpoint provisioning page (shareable, no operator auth) ----
    @app.get("/p/{token}", response_class=HTMLResponse)
    async def provision_page(token: str, request: Request):
        import json as _json
        import datetime as _dt
        from .models import ProvisioningToken, Endpoint
        from .api.endpoints import build_endpoint_bundle

        db = SessionLocal()
        try:
            pt = db.get(ProvisioningToken, token)
            if not pt or not pt.is_valid:
                return HTMLResponse(_PROVISION_INVALID, status_code=404)
            ep = db.get(Endpoint, pt.endpoint_id)
            if not ep:
                return HTMLResponse(_PROVISION_INVALID, status_code=404)
            bundle, ep = build_endpoint_bundle(db, ep)
            pt.used_count = (pt.used_count or 0) + 1
            db.commit()
            exp = pt.expires_at
            if exp is not None and exp.tzinfo is None:
                exp = exp.replace(tzinfo=_dt.timezone.utc)
            expires_human = _human_expiry(exp)
            return templates.TemplateResponse("provision.html", {
                "request": request,
                "endpoint_name": ep.name,
                "protocol": bundle.protocol,
                "os": bundle.os,
                "inspect_tls": bool(ep.inspect_tls),
                "qr": bundle.qr_png_b64,
                "filename": bundle.filename,
                "install_steps": bundle.install_steps,
                "config_json": _json.dumps(bundle.config_text),
                "filename_json": _json.dumps(bundle.filename),
                "base": settings.public_url.rstrip("/"),
                "domain": settings.domain,
                "expires_human": expires_human,
            })
        finally:
            db.close()

    # ---- Console (SPA-ish server-rendered shell) ----
    @app.get("/", response_class=HTMLResponse)
    async def console(request: Request, principal: Optional[Principal] = Depends(get_current_user)):
        if principal is None and not settings.is_dev:
            return RedirectResponse("/api/v1/auth/login")
        user = principal.to_dict() if principal else {
            "name": "Local Admin", "email": "admin@local", "roles": ["admin"], "uid": "local", "username": "local",
        }
        return templates.TemplateResponse("console.html", {
            "request": request,
            "user": user,
            "is_admin": principal.is_admin if principal else True,
            "domain": settings.domain,
            "env": settings.env,
        })

    @app.get("/healthz")
    async def healthz():
        return {"ok": True, "service": "fabric-management", "version": app.version}

    return app


app = create_app()
