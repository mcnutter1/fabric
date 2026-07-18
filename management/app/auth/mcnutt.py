"""McNutt Cloud auth primitives — HMAC signing/verification and API calls.

Mirrors the PHP client helper documented at https://login.mcnutt.cloud/docs/:
payloads are signed with base64url HMAC-SHA256 over the JSON body and must be
verified with the shared app_secret before being trusted.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any, Optional

import httpx

from ..config import settings


def b64url_encode(data: bytes) -> str:
    """Base64url with no padding (matches b64url_encode_c)."""
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def hmac_sign(payload_json: str, secret: Optional[str] = None) -> str:
    """Create a base64url HMAC-SHA256 signature (matches hmac_sign_c)."""
    secret = secret or settings.auth_app_secret
    digest = hmac.new(secret.encode(), payload_json.encode(), hashlib.sha256).digest()
    return b64url_encode(digest)


def verify_hmac(payload_json: str, sig: str, secret: Optional[str] = None) -> bool:
    """Constant-time compare an incoming signature (matches verify_hmac_c)."""
    expected = hmac_sign(payload_json, secret)
    return hmac.compare_digest(expected, sig)


def canonical_json(payload: Any) -> str:
    """Serialise like PHP json_encode(..., JSON_UNESCAPED_SLASHES)."""
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=False)


async def validate_session_token(token: str, client_ip: str = "") -> Optional[dict]:
    """Validate an SSO session token via /api/validate.php.

    Returns the verified payload (with roles injected) or None.
    """
    url = f"{settings.auth_login_base}/api/validate.php"
    params = {"token": token, "app_id": settings.auth_app_id}
    if client_ip:
        params["client_ip"] = client_ip
    return await _validate(url, params)


async def validate_api_key(api_key: str, client_ip: str = "") -> Optional[dict]:
    """Validate a personal (mcak_) or system (mcsak_) API key."""
    url = f"{settings.auth_login_base}/api/validate.php"
    params = {"api_key": api_key, "app_id": settings.auth_app_id}
    if client_ip:
        params["client_ip"] = client_ip
    return await _validate(url, params)


async def _validate(url: str, params: dict) -> Optional[dict]:
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, params=params)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    if not body.get("ok"):
        return None

    payload = body.get("payload")
    sig = body.get("sig")
    if payload is None or not sig:
        return None
    # Verify the signature over the canonical payload before trusting it.
    if not verify_hmac(canonical_json(payload), sig):
        return None

    result = dict(payload)
    result["roles"] = body.get("roles", payload.get("roles", []))
    return result


async def whoami(api_key: str) -> Optional[dict]:
    """Resolve an API key to identity via /api/whoami (Bearer)."""
    url = f"{settings.auth_login_base}/api/whoami"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers={"Authorization": f"Bearer {api_key}"})
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    if not body.get("ok"):
        return None
    return body
