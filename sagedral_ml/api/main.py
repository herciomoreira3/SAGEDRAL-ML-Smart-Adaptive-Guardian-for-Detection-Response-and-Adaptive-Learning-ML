"""
FastAPI Backend Application entrypoint.
Serves REST API endpoints, real-time WebSocket connection, and built React Dashboard static files.
"""

import os
import time
import json
import asyncio
import logging
import ipaddress
import threading
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import RequestValidationError

from sagedral_ml import __version__
from sagedral_ml.config import get_config
from sagedral_ml.database.connection import init_db
from sagedral_ml.database import crud
from sagedral_ml.api.websocket import ws_manager
from sagedral_ml.api.routers import alerts, blocked_ips, traffic, config as config_router, model as model_router, rules, auth as auth_router, enterprise
from sagedral_ml.auth.security import (
    seed_default_admin,
    decode_access_token,
    get_current_user,
)
from sagedral_ml.core.container import global_container
from sagedral_ml.api.rate_limit import limiter as _limiter, RATE_LIMITING_AVAILABLE
from sagedral_ml.observability import metrics, process_memory_rss_bytes
from sqlalchemy import text
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

if RATE_LIMITING_AVAILABLE:
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded
    logger.info("Rate limiter enabled (slowapi + memory backend).")
else:
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
                    firewall_ok = True
                    if ips_mod:
                        if "/" in item.ip:
                            firewall_ok = ips_mod.unblock_network(item.ip)
                        else:
                            firewall_ok = ips_mod.unblock_ip(item.ip)
                    if (
                        not firewall_ok
                        and bool(getattr(ips_mod, "enabled", False))
                    ):
                        logger.error(
                            "Auto-unblock retained DB block because firewall "
                            "removal failed for %s",
                            item.ip,
                        )
                        continue

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


async def drift_monitor_background_task():
    """Persist model drift state transitions for dashboard/operations."""
    last_detected = False
    while True:
        try:
            await asyncio.sleep(60)
            cfg = get_config()
            if not cfg.get("ml", "drift_enabled", True):
                continue
            engine = global_container.ml_engine
            if engine is None:
                continue
            threshold = float(
                cfg.get("ml", "drift_psi_threshold", 0.25) or 0.25
            )
            drift = engine.get_drift_status(threshold)
            detected = bool(drift.get("detected", False))
            metrics.set("sagedral_ml_drift_psi", drift.get("psi", 0.0))
            if detected and not last_detected:
                async with _db_conn.AsyncSessionLocal() as db:
                    await crud.create_system_event(
                        db,
                        "MODEL_DRIFT",
                        "WARNING",
                        "ml_engine",
                        "Model drift detected; retraining is recommended.",
                        drift,
                    )
                await ws_manager.broadcast("model_drift", drift)
            last_detected = detected
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Drift monitor error: %s", exc)


async def adaptive_learning_background_task():
    while True:
        try:
            cfg = get_config()
            interval = max(
                1,
                int(
                    cfg.get("ml", "feedback_retrain_interval_hours", 24)
                    or 24
                ),
            )
            await asyncio.sleep(interval * 3600)
            if not cfg.get("ml", "adaptive_learning_enabled", True):
                continue
            from sagedral_ml.adaptive import adaptive_learning_manager

            result = await adaptive_learning_manager.run_once()
            if result.get("trained"):
                await ws_manager.broadcast("model_retrained", result)
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("Adaptive learning task error: %s", exc)


async def ha_sync_background_task():
    while True:
        try:
            cfg = get_config()
            interval = max(
                5, int(cfg.get("ha", "sync_interval_seconds", 30) or 30)
            )
            await asyncio.sleep(interval)
            from sagedral_ml.ha import ha_sync_manager

            if ha_sync_manager.enabled():
                result = await ha_sync_manager.sync_once()
                metrics.set(
                    "sagedral_ha_peer_sync_success",
                    result.get("succeeded", 0),
                )
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("HA sync task error: %s", exc)


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
    drift_task = asyncio.create_task(drift_monitor_background_task())
    adaptive_task = asyncio.create_task(adaptive_learning_background_task())
    ha_task = asyncio.create_task(ha_sync_background_task())
    yield
    tasks = [
        unblock_task,
        retention_task,
        backup_task,
        drift_task,
        adaptive_task,
        ha_task,
    ]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("SAGEDRAL-ML API server shutdown.")


def create_app() -> FastAPI:
    config = get_config()

    app = FastAPI(
        title="SAGEDRAL-ML NIDPS System API",
        version=__version__,
        description="Smart Adaptive Guardian for Enhanced Detection, Response, and Adaptive Learning - ML",
        lifespan=lifespan,
    )

    rate_events = defaultdict(deque)
    rate_lock = threading.Lock()

    @app.middleware("http")
    async def global_api_rate_limit(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            peer = request.client.host if request.client else "unknown"
            trusted = set(config.get("api", "trusted_proxies", []) or [])
            client_key = peer
            if peer in trusted:
                forwarded = request.headers.get("x-forwarded-for", "")
                candidate = forwarded.split(",", 1)[0].strip()
                try:
                    client_key = str(ipaddress.ip_address(candidate))
                except ValueError:
                    client_key = peer
            maximum = max(
                1,
                int(
                    config.get(
                        "api", "global_rate_limit_per_minute", 600
                    )
                    or 600
                ),
            )
            now = time.monotonic()
            with rate_lock:
                events = rate_events[client_key]
                cutoff = now - 60.0
                while events and events[0] <= cutoff:
                    events.popleft()
                if len(events) >= maximum:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Global API rate limit exceeded"},
                        headers={"Retry-After": "60"},
                    )
                events.append(now)
                # Bound stale-key growth behind reverse proxies/scanners.
                if len(rate_events) > 10000:
                    stale = [
                        key
                        for key, values in rate_events.items()
                        if not values or values[-1] <= cutoff
                    ]
                    for key in stale[:5000]:
                        rate_events.pop(key, None)
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if config.get("api", "csp_enabled", True):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; style-src 'self' "
                "'unsafe-inline'; img-src 'self' data:; connect-src 'self' "
                "ws: wss:; font-src 'self'; object-src 'none'; "
                "base-uri 'self'; frame-ancestors 'none'"
            )
        return response

    if RATE_LIMITING_AVAILABLE:
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

    origins = config.get("api", "cors_origins", [])
    if not isinstance(origins, list):
        origins = []
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=origins != ["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth_router.router)
    app.include_router(alerts.router)
    app.include_router(blocked_ips.router)
    app.include_router(blocked_ips.whitelist_router)
    app.include_router(traffic.router)
    app.include_router(config_router.router)
    app.include_router(model_router.router)
    app.include_router(rules.router)
    app.include_router(enterprise.router)

    @app.get("/api/v1/status", tags=["System Status"])
    async def get_status():
        uptime = time.time() - START_TIME
        return {
            "status": "running",
            "uptime_seconds": int(uptime),
            "version": __version__,
        }

    @app.get("/api/v1/status/details", tags=["System Status"])
    async def get_status_details(
        _user=Depends(get_current_user),
    ):
        capture_mod = global_container.capture_module
        capture_stats = (
            capture_mod.get_stats()
            if capture_mod is not None
            else {"interface": None, "packets_received": 0, "is_running": False}
        )
        blocked_count = 0
        alerts_count = 0
        try:
            async with _db_conn.AsyncSessionLocal() as db:
                from sagedral_ml.database.models import AlertModel, BlockedIPModel
                from sqlalchemy import func, select

                blocked_result = await db.execute(
                    select(func.count(BlockedIPModel.id)).where(
                        BlockedIPModel.is_active == 1
                    )
                )
                alert_result = await db.execute(
                    select(func.count(AlertModel.id))
                )
                blocked_count = int(blocked_result.scalar() or 0)
                alerts_count = int(alert_result.scalar() or 0)
        except Exception:
            logger.debug("Detailed status counters unavailable", exc_info=True)
        engine = global_container.ml_engine
        return {
            "status": "running",
            "uptime_seconds": int(time.time() - START_TIME),
            "version": __version__,
            "interface": capture_stats.get("interface"),
            "capture_running": capture_stats.get("is_running", False),
            "packets_captured_total": capture_stats.get("packets_received", 0),
            "blocked_ips_count": blocked_count,
            "alerts_total_count": alerts_count,
            "ml_model_loaded": (
                bool(engine.model_loaded) if engine is not None else False
            ),
            "ml_model_version": (
                engine.version if engine is not None else "unattached"
            ),
        }

    @app.get("/api/v1/capture/stats", tags=["Capture"])
    async def get_capture_stats(_user=Depends(get_current_user)):
        capture_mod = global_container.capture_module
        if capture_mod is None:
            return {
                "status": "unavailable",
                "message": "Capture module not running (API-only mode or not started yet).",
                "is_running": False,
            }
        return capture_mod.get_stats()

    @app.get("/healthz", tags=["System Status"])
    async def healthz():
        unhealthy = []
        try:
            if _db_conn.AsyncSessionLocal is None:
                await init_db()
            async with _db_conn.AsyncSessionLocal() as db:
                await db.execute(text("SELECT 1"))
        except Exception:
            unhealthy.append("database")
        capture_mod = global_container.capture_module
        if capture_mod is not None and not capture_mod.is_running:
            unhealthy.append("capture")
        metrics.set("sagedral_health_status", 0 if unhealthy else 1)
        metrics.set("process_memory_rss_bytes", process_memory_rss_bytes())
        return JSONResponse(
            status_code=503 if unhealthy else 200,
            content={"ok": not unhealthy, "unhealthy_modules": unhealthy},
        )

    @app.get("/readyz", tags=["System Status"])
    async def readyz():
        engine = global_container.ml_engine
        # API-only mode is ready for administration even without an attached
        # orchestrator; full mode additionally requires an operational model.
        ready = engine is None or bool(getattr(engine, "model_loaded", False))
        return JSONResponse(
            status_code=200 if ready else 503,
            content={
                "ready": ready,
                "api": True,
                "websocket_manager": True,
                "ml_model_loaded": (
                    None if engine is None else bool(engine.model_loaded)
                ),
            },
        )

    @app.get("/metrics", include_in_schema=False)
    async def prometheus_metrics():
        if not config.get("api", "metrics_enabled", True):
            raise HTTPException(status_code=404, detail="Metrics disabled")
        capture_mod = global_container.capture_module
        if capture_mod is not None:
            stats = capture_mod.get_stats()
            metrics.set(
                "sagedral_capture_packets_total",
                stats.get("packets_received", 0),
            )
            metrics.set(
                "sagedral_capture_drops_total",
                stats.get("packets_dropped_queue_full", 0),
            )
            metrics.set(
                "sagedral_capture_kernel_drops_total",
                stats.get("kernel_drops", 0),
            )
        try:
            from sagedral_ml.database.models import AlertModel, BlockedIPModel
            from sqlalchemy import func, select

            async with _db_conn.AsyncSessionLocal() as db:
                blocked_result = await db.execute(
                    select(func.count(BlockedIPModel.id)).where(
                        BlockedIPModel.is_active == 1
                    )
                )
                metrics.set(
                    "sagedral_blocked_ips_active",
                    int(blocked_result.scalar() or 0),
                )
                for severity_name in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                    alert_result = await db.execute(
                        select(func.count(AlertModel.id)).where(
                            AlertModel.severity == severity_name
                        )
                    )
                    metrics.set(
                        "sagedral_alerts_persisted",
                        int(alert_result.scalar() or 0),
                        labels={"severity": severity_name},
                    )
        except Exception:
            logger.debug("Could not collect database metrics", exc_info=True)
        return Response(
            content=metrics.render(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )

    @app.websocket("/ws/alerts")
    async def websocket_alerts(websocket: WebSocket):
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=1008)
            return
        try:
            claims = decode_access_token(token)
            user_id = int(claims.get("sub", "0"))
            if _db_conn.AsyncSessionLocal is None:
                await init_db()
            from sagedral_ml.database.models import UserModel
            from sqlalchemy import select

            async with _db_conn.AsyncSessionLocal() as db:
                result = await db.execute(
                    select(UserModel).where(UserModel.id == user_id)
                )
                websocket_user = result.scalar_one_or_none()
            if websocket_user is None or not bool(websocket_user.is_active):
                raise ValueError("inactive websocket user")
        except Exception:
            await websocket.close(code=1008)
            return

        await ws_manager.connect(websocket)
        try:
            while True:
                try:
                    data = await asyncio.wait_for(
                        websocket.receive_text(), timeout=30
                    )
                except asyncio.TimeoutError:
                    await ws_manager.ping(websocket)
                    continue
                try:
                    message = json.loads(data)
                except (TypeError, ValueError):
                    continue
                action = message.get("action") or message.get("event")
                if action == "ping":
                    await websocket.send_text('{"event":"pong","data":{}}')
                elif action == "subscribe":
                    subscriptions = ws_manager.subscribe(
                        websocket, message.get("topic", "*")
                    )
                    await websocket.send_json(
                        {
                            "event": "subscribed",
                            "data": {"topics": sorted(subscriptions)},
                        }
                    )
                elif action == "unsubscribe":
                    subscriptions = ws_manager.unsubscribe(
                        websocket, message.get("topic", "")
                    )
                    await websocket.send_json(
                        {
                            "event": "subscribed",
                            "data": {"topics": sorted(subscriptions)},
                        }
                    )
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
