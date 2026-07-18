"""Auth routes — McNutt Cloud SSO callback, logout, and identity."""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

from ..auth import Principal, get_current_user, issue_session_cookie, mcnutt
from ..config import settings

log = logging.getLogger("fabric.auth")

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login")
async def login(request: Request):
    """Kick off SSO by redirecting to the central login UI with our callback."""
    callback = f"{settings.public_url}/api/v1/auth/callback"
    url = (
        f"{settings.auth_login_base}/?app_id={settings.auth_app_id}"
        f"&return_url={callback}"
    )
    return RedirectResponse(url)


@router.get("/callback")
async def callback(request: Request):
    """Handle payload/sig redirect from the login service and set a session cookie."""
    payload_raw = request.query_params.get("payload")
    sig = request.query_params.get("sig")
    if not payload_raw or not sig:
        log.warning("SSO callback missing payload/sig (payload=%s sig=%s)",
                    bool(payload_raw), bool(sig))
        return RedirectResponse("/api/v1/auth/denied")

    if not settings.auth_app_secret:
        log.error("SSO callback cannot verify: FABRIC_AUTH_APP_SECRET is not set")
        return RedirectResponse("/api/v1/auth/denied")

    payload = mcnutt.verify_redirect_payload(payload_raw, sig)
    if payload is None:
        report = mcnutt.diagnose_redirect(payload_raw, sig)
        log.warning("SSO callback signature verification FAILED: %s", report)
        # Optionally expose the (secret-free) diagnostic in the response for
        # troubleshooting; off by default to avoid leaking the identity payload.
        if settings.is_dev or settings.auth_debug:
            return JSONResponse(
                {"ok": False, "reason": "access_denied", "diagnostic": report},
                status_code=403,
            )
        return RedirectResponse("/api/v1/auth/denied")

    principal = Principal.from_payload(payload)
    cookie = issue_session_cookie(principal)
    resp = RedirectResponse("/")
    resp.set_cookie(
        settings.auth_cookie_name, cookie,
        max_age=settings.auth_ttl_sec, httponly=True,
        samesite="lax", secure=not settings.is_dev,
        domain=settings.auth_cookie_domain if not settings.is_dev else None,
    )
    return resp


@router.get("/denied")
async def denied():
    return JSONResponse({"ok": False, "reason": "access_denied"}, status_code=403)


@router.get("/logout")
async def logout(request: Request):
    resp = RedirectResponse(f"{settings.auth_login_base}/api/logout.php")
    resp.delete_cookie(settings.auth_cookie_name)
    return resp


@router.get("/me")
async def me(principal: Optional[Principal] = Depends(get_current_user)):
    if not principal:
        return JSONResponse({"authenticated": False}, status_code=401)
    return {"authenticated": True, "is_admin": principal.is_admin, **principal.to_dict()}
