"""Realtime event hub — fans node telemetry out to operator UIs.

In-process asyncio pub/sub by default; if FABRIC_EVENTBUS_URL is a redis:// URL,
events are published to Redis so any manager replica can broadcast to any
connected browser (HA). Node agents and browsers each hold a WebSocket; the hub
routes events between them.
"""
from __future__ import annotations

import asyncio
import json
from typing import Any, Optional

from ..config import settings


class EventHub:
    def __init__(self) -> None:
        self._ui_subscribers: set[asyncio.Queue] = set()
        self._redis = None
        self._redis_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        if settings.eventbus_url.startswith("redis://"):
            try:
                import redis.asyncio as aioredis
                self._redis = aioredis.from_url(settings.eventbus_url, decode_responses=True)
                self._redis_task = asyncio.create_task(self._redis_listen())
            except Exception:
                self._redis = None

    async def stop(self) -> None:
        if self._redis_task:
            self._redis_task.cancel()
        if self._redis:
            await self._redis.close()

    # ------------------------------------------------------------------ UI subscribers
    def subscribe_ui(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._ui_subscribers.add(q)
        return q

    def unsubscribe_ui(self, q: asyncio.Queue) -> None:
        self._ui_subscribers.discard(q)

    # ------------------------------------------------------------------ publish
    async def publish(self, event_type: str, data: Any) -> None:
        event = {"type": event_type, "data": data}
        if self._redis:
            try:
                await self._redis.publish("fabric-events", json.dumps(event, default=str))
                return
            except Exception:
                pass
        await self._fanout(event)

    async def _fanout(self, event: dict) -> None:
        dead = []
        for q in list(self._ui_subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self._ui_subscribers.discard(q)

    async def _redis_listen(self) -> None:
        assert self._redis is not None
        pubsub = self._redis.pubsub()
        await pubsub.subscribe("fabric-events")
        async for message in pubsub.listen():
            if message.get("type") != "message":
                continue
            try:
                event = json.loads(message["data"])
            except (ValueError, KeyError):
                continue
            await self._fanout(event)


hub = EventHub()
