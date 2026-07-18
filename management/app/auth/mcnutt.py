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
    """Serialise like PHP ``json_encode($payload, JSON_UNESCAPED_SLASHES)``.

    PHP escapes non-ASCII as \\uXXXX by default (JSON_UNESCAPED_UNICODE is NOT
    set here) and leaves forward slashes unescaped. ``ensure_ascii=True`` matches
    the unicode escaping; Python never escapes slashes, matching the slash flag.
    """
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True)


def verify_redirect_payload(payload_raw: str, sig: str) -> Optional[dict]:
    """Verify an SSO redirect's ``payload``+``sig`` and return the parsed dict.

    The login server signs ``json_encode($payload, JSON_UNESCAPED_SLASHES)``.
    We re-encode the decoded payload to match, but also accept the raw query
    string as a fallback in case the server signed it verbatim. Returns the
    payload dict on success, or ``None`` if it cannot be trusted.
    """
    try:
        payload = json.loads(payload_raw)
    except ValueError:
        return None
    candidates = (canonical_json(payload), payload_raw)
    for candidate in candidates:
        if verify_hmac(candidate, sig):
            return payload
    return None


def signature_candidates(payload_raw: str) -> dict[str, str]:
    """Return a set of candidate signing strings for diagnostics.

    Maps a human label to the exact string variant; the caller can HMAC each and
    compare against the received signature to discover the server's convention.
    """
    variants: dict[str, str] = {"raw_query": payload_raw}
    try:
        payload = json.loads(payload_raw)
    except ValueError:
        return variants
    variants["compact_ascii"] = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    variants["compact_unicode"] = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    variants["compact_ascii_slashesc"] = json.dumps(
        payload, separators=(",", ":"), ensure_ascii=True
    ).replace("/", "\\/")
    variants["compact_unicode_slashesc"] = json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False
    ).replace("/", "\\/")
    variants["py_default"] = json.dumps(payload)  # ", " / ": " spacing, ascii
    variants["sorted_ascii"] = json.dumps(
        payload, separators=(",", ":"), ensure_ascii=True, sort_keys=True
    )
    try:
        variants["b64url_decoded"] = b64url_decode(payload_raw).decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        pass
    return variants


def diagnose_redirect(payload_raw: str, sig: str) -> dict[str, Any]:
    """Build a redacted diagnostic report for a failing SSO redirect.

    Never includes the app secret. Shows which (if any) signing convention
    reproduces the received signature.
    """
    report: dict[str, Any] = {
        "app_id": settings.auth_app_id,
        "app_secret_set": bool(settings.auth_app_secret),
        "app_secret_len": len(settings.auth_app_secret or ""),
        "payload_len": len(payload_raw),
        "sig_received": sig,
        "sig_received_len": len(sig),
        "matched_variant": None,
        "variants": {},
    }
    for label, candidate in signature_candidates(payload_raw).items():
        computed = hmac_sign(candidate)
        match = hmac.compare_digest(computed, sig)
        report["variants"][label] = {"sig": computed, "match": match}
        if match and report["matched_variant"] is None:
            report["matched_variant"] = label
    return report




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
