"""Active-passive HA blocklist synchronization helpers."""

import asyncio
import hmac
import json
import logging
import socket
from typing import Any, Dict, List
from urllib import request

from sagedral_ml.config import get_config
from sagedral_ml.database import crud
import sagedral_ml.database.connection as db_connection

logger = logging.getLogger("sagedral_ml.ha")


class HASyncManager:
    def __init__(self, config=None) -> None:
        self.config = config or get_config()

    def enabled(self) -> bool:
        return bool(self.config.get("ha", "enabled", False))

    def node_id(self) -> str:
        return str(
            self.config.get("ha", "node_id", "") or socket.gethostname()
        )

    def valid_secret(self, provided: str) -> bool:
        expected = str(self.config.get("ha", "shared_secret", "") or "")
        return bool(expected) and hmac.compare_digest(
            expected.encode("utf-8"), str(provided or "").encode("utf-8")
        )

    @staticmethod
    def _post(url: str, payload: Dict[str, Any], secret: str) -> None:
        endpoint = url.rstrip("/") + "/api/v1/ha/blocklist"
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            endpoint,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-Sagedral-HA-Key": secret,
            },
        )
        with request.urlopen(req, timeout=10) as response:
            if int(response.status) >= 400:
                raise RuntimeError("HA peer returned HTTP %s" % response.status)

    async def sync_once(self) -> Dict[str, Any]:
        if not self.enabled():
            return {"enabled": False, "peers": 0}
        secret = str(self.config.get("ha", "shared_secret", "") or "")
        peers = self.config.get("ha", "peer_urls", []) or []
        if not secret:
            return {"enabled": True, "error": "shared_secret_missing", "peers": 0}
        async with db_connection.AsyncSessionLocal() as db:
            rows = await crud.get_active_blocked_ips(db)
        payload = {
            "source_node": self.node_id(),
            "blocked_ips": [
                {
                    "ip": row.ip,
                    "reason": row.reason,
                    "auto_unblock_at": row.auto_unblock_at,
                    "blocked_at": row.blocked_at,
                }
                for row in rows
            ],
        }
        loop = asyncio.get_running_loop()
        succeeded = 0
        errors = []
        for peer in peers:
            try:
                await loop.run_in_executor(
                    None, self._post, str(peer), payload, secret
                )
                succeeded += 1
            except Exception as exc:
                errors.append({"peer": str(peer), "error": str(exc)})
        return {
            "enabled": True,
            "peers": len(peers),
            "succeeded": succeeded,
            "errors": errors,
        }


ha_sync_manager = HASyncManager()

