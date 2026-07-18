"""WebSocket endpoints for the real-time console."""
from __future__ import annotations

import asyncio
import contextlib

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..auth.session import read_session_cookie
from ..config import settings
from ..realtime import hub

router = APIRouter()


@router.websocket("/ws/ui")
async def ws_ui(websocket: WebSocket):
    # Authenticate the operator from the session cookie before accepting.
    raw = websocket.cookies.get(settings.auth_cookie_name)
    principal = read_session_cookie(raw) if raw else None
    if principal is None and not settings.is_dev:
        await websocket.close(code=4401)
        return
    await websocket.accept()

    queue = hub.subscribe_ui()
    await websocket.send_json({"type": "hello", "data": {"ok": True}})
    try:
        while True:
            event = await queue.get()
            await websocket.send_json(event)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.unsubscribe_ui(queue)
        with contextlib.suppress(Exception):
            await websocket.close()
