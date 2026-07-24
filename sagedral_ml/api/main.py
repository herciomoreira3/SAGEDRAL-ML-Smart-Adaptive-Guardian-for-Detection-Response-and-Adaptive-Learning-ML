"""
FastAPI Backend Application entrypoint.
Serves REST API endpoints, real-time WebSocket connection, and built React Dashboard static files.
"""

import os
import time
import asyncio
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from sagedral_ml import __version__
from sagedral_ml.config import get_config
from sagedral_ml.database.connection import init_db
from sagedral_ml.database import crud
from sagedral_ml.api.websocket import ws_manager
from sagedral_ml.api.routers import alerts, blocked_ips, traffic, config as config_router, model as model_router, rules
import sagedral_ml.database.connection as _db_conn

logger = logging.getLogger("sagedral_ml.api")

START_TIME = time.time()


async def auto_unblock_background_task():
    """Background task running every 60s to check and auto-unblock expired IPs."""
    while True:
        try:
            await asyncio.sleep(60)
            async with _db_conn.AsyncSessionLocal() as db:
                expired = await crud.get_expired_blocked_ips(db)
                for item in expired:
                    # Unblock in IPS module
                    ips_mod = getattr(blocked_ips.router, "ips_module", None)
                    if ips_mod:
                        ips_mod.unblock_ip(item.ip)

                    await crud.unblock_ip_db(db, item.ip)
                    logger.info(f"Auto-unblocked expired IP {item.ip}")

                    # Broadcast event via WebSocket
                    await ws_manager.broadcast("ip_unblocked", {"ip": item.ip, "timestamp": time.time()})
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in auto-unblock background task: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Initializing SAGEDRAL-ML API server...")
    await init_db()
    unblock_task = asyncio.create_task(auto_unblock_background_task())
    yield
    # Shutdown
    unblock_task.cancel()
    logger.info("SAGEDRAL-ML API server shutdown.")


def create_app() -> FastAPI:
    config = get_config()

    app = FastAPI(
        title="SAGEDRAL-ML NIDPS System API",
        version=__version__,
        description="Smart Adaptive Guardian for Enhanced Detection, Response, and Adaptive Learning - ML",
        lifespan=lifespan,
    )

    # CORS configuration
    origins = config.get("api", "cors_origins", ["*"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins != ["*"] else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include routers
    app.include_router(alerts.router)
    app.include_router(blocked_ips.router)
    app.include_router(traffic.router)
    app.include_router(config_router.router)
    app.include_router(model_router.router)
    app.include_router(rules.router)

    # Status endpoint
    @app.get("/api/v1/status", tags=["System Status"])
    async def get_status():
        uptime = time.time() - START_TIME
        iface = config.get("capture", "interface", "eth0")
        blocked_count = 0
        try:
            if _db_conn.AsyncSessionLocal is not None:
                async with _db_conn.AsyncSessionLocal() as db:
                    active_blocked = await crud.get_active_blocked_ips(db)
                    blocked_count = len(active_blocked)
        except Exception:
            pass

        return {
            "status": "running",
            "uptime_seconds": int(uptime),
            "interface": iface,
            "version": __version__,
            "blocked_ips_count": blocked_count,
            "ml_model_loaded": getattr(model_router.router, "ml_engine", None).model_loaded if getattr(model_router.router, "ml_engine", None) else False,
        }

    # WebSocket endpoint
    @app.websocket("/ws/alerts")
    async def websocket_alerts(websocket: WebSocket):
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                # Optional ping-pong
                if data == '{"event":"ping"}':
                    await websocket.send_text('{"event":"pong"}')
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception as e:
            logger.debug(f"WebSocket connection error: {e}")
            ws_manager.disconnect(websocket)

    # Static files serving for built React Dashboard
    static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
    if os.path.exists(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


app = create_app()
