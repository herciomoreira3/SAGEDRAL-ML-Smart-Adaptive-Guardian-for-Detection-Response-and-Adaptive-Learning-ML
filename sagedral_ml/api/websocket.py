"""
WebSocket connection manager for real-time dashboard events.
"""

import json
import logging
from typing import List
from fastapi import WebSocket

logger = logging.getLogger("sagedral_ml.api.websocket")


class ConnectionManager:
    """
    Manages active WebSocket connections and broadcasts JSON event payloads.
    """

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total active connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected. Remaining connections: {len(self.active_connections)}")

    async def broadcast(self, event: str, data: dict):
        """Broadcast event JSON payload to all connected clients."""
        if not self.active_connections:
            return

        payload = json.dumps({"event": event, "data": data})
        disconnected = []

        for connection in list(self.active_connections):
            try:
                await connection.send_text(payload)
            except Exception as e:
                logger.debug(f"Failed to send to WebSocket connection: {e}")
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)


ws_manager = ConnectionManager()
