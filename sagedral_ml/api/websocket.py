"""Authenticated WebSocket manager with topics, keepalive, and replay buffer."""

import asyncio
import json
import logging
import threading
from collections import deque
from typing import Deque, Dict, Optional, Set

from fastapi import WebSocket

logger = logging.getLogger("sagedral_ml.api.websocket")


class ConnectionManager:
    """Manage WebSocket subscriptions on the owning ASGI event loop."""

    def __init__(self, buffer_size: int = 1000) -> None:
        self.active_connections = []  # compatibility with existing callers/tests
        self.active_subscriptions = {}  # type: Dict[WebSocket, Set[str]]
        self._event_buffer = deque(maxlen=buffer_size)  # type: Deque[str]
        self._loop = None  # type: Optional[asyncio.AbstractEventLoop]
        self._buffer_lock = threading.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._loop = asyncio.get_running_loop()
        self.active_connections.append(websocket)
        self.active_subscriptions[websocket] = {"*"}
        with self._buffer_lock:
            catchup = list(self._event_buffer)[-20:]
        for payload in catchup:
            await websocket.send_text(payload)
        logger.info(
            "WebSocket client connected. Total active connections: %d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        self.active_subscriptions.pop(websocket, None)

    def subscribe(self, websocket: WebSocket, topic: str) -> Set[str]:
        topic = str(topic or "").strip()
        if not topic or len(topic) > 100:
            return set(self.active_subscriptions.get(websocket, set()))
        subscriptions = self.active_subscriptions.setdefault(websocket, set())
        if topic == "*":
            subscriptions.clear()
            subscriptions.add("*")
        else:
            subscriptions.discard("*")
            subscriptions.add(topic)
        return set(subscriptions)

    def unsubscribe(self, websocket: WebSocket, topic: str) -> Set[str]:
        subscriptions = self.active_subscriptions.setdefault(websocket, set())
        subscriptions.discard(str(topic))
        if not subscriptions:
            subscriptions.add("*")
        return set(subscriptions)

    @staticmethod
    def _matches(subscriptions: Set[str], event: str, data: dict) -> bool:
        if "*" in subscriptions or event in subscriptions:
            return True
        severity = str(data.get("severity", "")).lower()
        derived = {
            event.split("_", 1)[0] + ":*",
            "alerts:%s" % severity if event == "new_alert" else "",
            "alerts:severity:%s" % severity if event == "new_alert" else "",
            "blocked_ips:*" if event.startswith("ip_") else "",
            "traffic:*" if event == "traffic_stats" else "",
        }
        return bool(subscriptions.intersection(item for item in derived if item))

    async def _broadcast_local(self, event: str, data: dict, payload: str) -> None:
        disconnected = []
        for connection in list(self.active_connections):
            subscriptions = self.active_subscriptions.get(connection, {"*"})
            if not self._matches(subscriptions, event, data):
                continue
            try:
                await connection.send_text(payload)
            except Exception as exc:
                logger.debug("Failed to send WebSocket event: %s", exc)
                disconnected.append(connection)
        for connection in disconnected:
            self.disconnect(connection)

    async def broadcast(self, event: str, data: dict) -> None:
        payload = json.dumps({"event": event, "data": data}, default=str)
        with self._buffer_lock:
            self._event_buffer.append(payload)
        if not self.active_connections or self._loop is None:
            return
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            current_loop = None
        if current_loop is self._loop:
            await self._broadcast_local(event, data, payload)
        else:
            asyncio.run_coroutine_threadsafe(
                self._broadcast_local(event, data, payload), self._loop
            )

    async def ping(self, websocket: WebSocket) -> None:
        await websocket.send_text('{"event":"ping","data":{}}')


ws_manager = ConnectionManager()
