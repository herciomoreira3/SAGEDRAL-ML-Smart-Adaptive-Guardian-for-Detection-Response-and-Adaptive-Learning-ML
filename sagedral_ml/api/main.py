"""
FastAPI Backend Application entrypoint.
Serves REST API endpoints, real-time WebSocket connection, and built React Dashboard static files.
"""

import os
import time
import json
import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from sagedral_ml import __version__
from sagedral_ml.config import get_config
from sagedral_ml.database.connection import init_db
from sagedral_ml.database import crud
from sagedral_ml.api.websocket import ws_manager
from sagedral_ml.api.routers import alerts, blocked_ips, traffic, config as config_router, model as model_router, rules, auth as auth_router
from sagedral_ml.auth.security import seed_default_admin, decode_access_token
from sagedral_ml.core.container import global_container
import sagedral_ml.database.connection as _db_conn

logger = logging.getLogger("sagedral_ml.api")

try:
    from pythonjsonlogger import jsonlogger

    _json_handler = logging.StreamHandler()
    _json_formatter = jsonlogger.JsonFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s %(module)s %(funcName)s %(lineno)d"
    )
    _json_handler.setFormatter(_json_formatter)
    _root_logger = logging.getLogger()
    if not _root_logger.handlers:
        _root_logger.addHandler(_json_handler)
    _root_logger.setLevel(logging.INFO)
    logger.info("Structured JSON logging enabled (python-json-logger).")
except ImportError:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("Fallback default logging enabled. Install python-json-logger for structured JSON logs.")

START_TIME = time.time()

_limiter = None
try:
    from slowapi import Limiter, _rate_limit_exceeded_handler
    from slowapi.util import get_remote_address
    from slowapi.errors import RateLimitExceeded

    _limiter = Limiter(key_func=get_remote_address)
    logger.info("Rate limiter enabled (slowapi + memory backend).")
except ImportError:
    _limiter = None
    logger.info(
        "Rate limiter DISABLED. Package 'slowapi' not installed. Install it manually: pip install slowapi limits"
    )


async def auto_unblock_background_task():
    """Background task running every 60s to check and auto-unblock expired IPs."""
    while True:
        try:
            await asyncio.sleep(60)
            ips_mod = global_container.ips_module
            async with _db_conn.AsyncSessionLocal() as db:
                expired = await crud.get_expired_blocked_ips(db)
                for item in expired:
                    if ips_mod:
                        ips_mod.unblock_ip(item.ip)

                    await crud.unblock_ip_db(db, item.ip)
                    logger.info(f"Auto-unblocked expired IP {item.ip}")

                    await ws_manager.broadcast("ip_unblocked", {"ip": item.ip, "timestamp": time.time()})
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in auto-unblock background task: {e}")


async def retention_cleanup_background_task():
    """Run database retention cleanup every hour (CRIT-005)."""
    while True:
        try:
            await asyncio.sleep(3600)
            cfg = get_config()
            ret_alerts = int(cfg.get("database", "retention_days_alerts", 30) or 30)
            ret_traffic = int(cfg.get("database", "retention_days_traffic", 7) or 7)
            async with _db_conn.AsyncSessionLocal() as db:
                await crud.cleanup_old_records(db, ret_alerts, ret_traffic)
                logger.info(
                    "Retention cleanup executed (alerts=%dd, traffic=%dd).",
                    ret_alerts,
                    ret_traffic,
                )
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in retention cleanup background task: {e}")


async def backup_background_task():
    """Scheduled SQLite backup based on database.backup_interval_hours."""
    while True:
        try:
            cfg = get_config()
            interval_hours = int(cfg.get("database", "backup_interval_hours", 24) or 24)
            if interval_hours <= 0:
                interval_hours = 24
            await asyncio.sleep(interval_hours * 3600)

            from sagedral_ml.database.backup import DatabaseBackupManager

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, DatabaseBackupManager(cfg).run_full_backup)
            if result:
                logger.info("Scheduled database backup completed: %s", result)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Error in backup background task: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing SAGEDRAL-ML API server...")
    await init_db()
    try:
        async with _db_conn.AsyncSessionLocal() as db:
            await seed_default_admin(db)
    except Exception as e:
        logger.error(f"Gagal seed default admin saat startup: {e}")
    unblock_task = asyncio.create_task(auto_unblock_background_task())
    retention_task = asyncio.create_task(retention_cleanup_background_task())
    backup_task = asyncio.create_task(backup_background_task())
    yield
    unblock_task.cancel()
    retention_task.cancel()
    backup_task.cancel()
    logger.info("SAGEDRAL-ML API server shutdown.")


def create_app() -> FastAPI:
    config = get_config()

    app = FastAPI(
        title="SAGEDRAL-ML NIDPS System API",
        version=__version__,
        description="Smart Adaptive Guardian for Enhanced Detection, Response, and Adaptive Learning - ML",
        lifespan=lifespan,
    )

    if _limiter is not None:
        app.state.limiter = _limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        err_id = f"err-{int(time.time()*1000)}"
        logger.exception(f"[{err_id}] Unhandled exception at {request.url}: {exc}", exc_info=exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error_id": err_id,
                "type": exc.__class__.__name__,
                "detail": "Internal server error. Contact administrator if problem persists.",
                "path": str(request.url.path),
                "timestamp": time.time(),
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        errors: List[Dict[str, Any]] = []
        for err in exc.errors():
            loc = err.get("loc", [])
            errors.append({
                "field": ".".join(str(x) for x in loc),
                "message": err.get("msg", "Invalid input"),
                "type": err.get("type", "validation_error"),
            })
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Request validation failed",
                "errors": errors,
                "path": str(request.url.path),
                "timestamp": time.time(),
            },
        )

    origins = config.get("api", "cors_origins", ["*"])
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins if origins != ["*"] else ["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    if _limiter is not None:
        try:
            blocked_ips.manual_block_ip = _limiter.limit("10/minute")(blocked_ips.manual_block_ip)
            logger.info("Attached rate limit 10/min to manual_block_ip")
        except Exception as e:
            logger.warning(f"Could not attach rate limit to manual_block_ip: {e}")

        try:
            config_router.update_system_config = _limiter.limit("5/minute")(config_router.update_system_config)
            logger.info("Attached rate limit 5/min to update_system_config")
        except Exception as e:
            logger.warning(f"Could not attach rate limit to update_system_config: {e}")

        try:
            rules.create_custom_rule = _limiter.limit("3/minute")(rules.create_custom_rule)
            logger.info("Attached rate limit 3/min to create_custom_rule")
        except Exception as e:
            logger.warning(f"Could not attach rate limit to create_custom_rule: {e}")

    app.include_router(auth_router.router)
    app.include_router(alerts.router)
    app.include_router(blocked_ips.router)
    app.include_router(traffic.router)
    app.include_router(config_router.router)
    app.include_router(model_router.router)
    app.include_router(rules.router)

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
            "ml_model_loaded": bool(
                global_container.ml_engine.model_loaded
                if global_container.ml_engine is not None
                else False
            ),
        }

    @app.get("/api/v1/capture/stats", tags=["Capture"])
    async def get_capture_stats():
        capture_mod = global_container.capture_module
        if capture_mod is None:
            return {
                "status": "unavailable",
                "message": "Capture module not running (API-only mode or not started yet).",
                "is_running": False,
            }
        return capture_mod.get_stats()

    @app.websocket("/ws/alerts")
    async def websocket_alerts(websocket: WebSocket):
        token = websocket.query_params.get("token")
        if token:
            try:
                decode_access_token(token)
            except Exception:
                await websocket.close(code=1008)
                return

        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                if data == '{"event":"ping"}':
                    await websocket.send_text('{"event":"pong"}')
        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)
        except Exception as e:
            logger.debug(f"WebSocket connection error: {e}")
            ws_manager.disconnect(websocket)

    static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
    if os.path.exists(static_dir):
        app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

    return app


app = create_app()
