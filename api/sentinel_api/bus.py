"""Tiny in-process broadcaster for the console's live stream (Server-Sent Events)."""
from __future__ import annotations

import asyncio
import json
from typing import Any


class Bus:
    def __init__(self) -> None:
        self._subs: set[asyncio.Queue[str]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue[str]:
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=256)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._subs.discard(q)

    def publish(self, kind: str, data: dict[str, Any]) -> None:
        """Safe to call from sync route handlers running in the threadpool."""
        msg = json.dumps({"type": kind, "data": data}, default=str)
        if not self._loop:
            return
        self._loop.call_soon_threadsafe(self._fanout, msg)

    def _fanout(self, msg: str) -> None:
        for q in list(self._subs):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # slow client: drop; it will refetch on reconnect


bus = Bus()
