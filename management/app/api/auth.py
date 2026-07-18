"""Auth routes — McNutt Cloud SSO callback, logout, and identity."""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse

from ..auth import Principal, get_current_user, issue_session_cookie, mcnutt
from ..config import settings

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/login")
async def login(request: Request):
    """Kick off SSO by redirecting to the central login UI with our callback."""
    callback = f"{settings.public_url}/auth/callback"
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
        return RedirectResponse("/auth/denied")

    import json
    try:
        payload = json.loads(payload_raw)
    except ValueError:
        return RedirectResponse("/auth/denied")

    if not mcnutt.verify_hmac(mcnutt.canonical_json(payload), sig):
        return RedirectResponse("/auth/denied")

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
