"""
SAGEDRAL-ML System Orchestrator.
Coordinates CaptureThread, ProcessingThread (FlowExtractor + Signature + ML + Decision + IPS),
and FastAPI Uvicorn ASGI server with clean multi-thread shutdown handling.
"""

import sagedral_ml
import sys
import warnings
# === FIX NUMPY WSL longdouble warning (cosmetic only; TIDAK PENGARUH detection) ===
# WSL build numpy kadang compiled tanpa extended precision longdouble.
# SAGEDRAL HANYA menggunakan float64/int32; longdouble TIDAK PERNAH dipakai.
warnings.filterwarnings(
    "ignore",
    message=r".*longdouble.*Signature.*does not match any known type.*",
    category=UserWarning,
    module=r"numpy\._core\.getlimits",
)
try:
    import numpy as _np_warn_hack  # noqa: F401 — trigger numpy init sekarang
except Exception:
    pass
import time
import queue
import signal
import threading
import logging
import asyncio
import uvicorn

from sagedral_ml.config import get_config
from sagedral_ml.capture.sniffer import PacketCapture
from sagedral_ml.features.extractor import FlowAggregator
from sagedral_ml.detection.signature_engine import SignatureEngine
from sagedral_ml.detection.ml_engine import MLEngine
from sagedral_ml.detection.decision_engine import DecisionEngine
from sagedral_ml.ips.response import IPSModule
from sagedral_ml.ips.models import AlertEvent
import sagedral_ml.database.connection as _db_conn
from sagedral_ml.database import crud
from sagedral_ml.api.main import app
from sagedral_ml.api.websocket import ws_manager
from sagedral_ml.api.routers import blocked_ips, model as model_router

logger = logging.getLogger("sagedral_ml.main")

stop_event = threading.Event()


def processing_worker(
    packet_queue: queue.Queue,
    flow_queue: queue.Queue,
    flow_aggregator: FlowAggregator,
    signature_engine: SignatureEngine,
    ml_engine: MLEngine,
    decision_engine: DecisionEngine,
    ips_module: IPSModule,
):
    """
    Worker thread that pops raw packets, aggregates flows, performs signature + ML detection,
    executes IPS block actions, persists alerts to SQLite, and broadcasts via WebSockets.
    """
    logger.info("Processing worker thread started.")
    last_cleanup = time.time()
    last_stats_collect = time.time()
    packet_counter = 0
    bytes_counter = 0

    while not stop_event.is_set():
        current_time = time.time()

        # 1. Process packet queue
        try:
            packet = packet_queue.get(timeout=0.2)
            packet_counter += 1
            if hasattr(packet, "__len__"):
                bytes_counter += len(packet)
            flow_aggregator.process_packet(packet)
        except queue.Empty:
            pass

        # 2. Process completed flows queue
        try:
            flow_record = flow_queue.get_nowait()
            feature_vector = flow_record.to_feature_vector()

            # Hybrid Detection
            sig_result = signature_engine.evaluate(feature_vector)
            ml_result = ml_engine.predict(feature_vector)
            decision = decision_engine.decide(sig_result, ml_result, src_ip=flow_record.src_ip, now=current_time)

            if decision.is_threat or decision.action in ("BLOCK", "ALERT"):
                alert_event = AlertEvent(
                    timestamp=current_time,
                    src_ip=flow_record.src_ip,
                    dst_ip=flow_record.dst_ip,
                    src_port=flow_record.src_port,
                    dst_port=flow_record.dst_port,
                    protocol="TCP" if flow_record.protocol == 6 else ("UDP" if flow_record.protocol == 17 else "ICMP"),
                    attack_type=decision.attack_type,
                    severity=decision.severity,
                    final_score=decision.final_score,
                    action_taken=decision.action,
                    signature_matched=sig_result.matched_rules,
                    ml_anomaly_score=ml_result.anomaly_score,
                    flow_duration=feature_vector["duration"],
                    total_bytes=flow_record.total_fwd_bytes + flow_record.total_bwd_bytes,
                )

                # IPS Firewall Execution
                if decision.action == "BLOCK":
                    ips_success = ips_module.block_ip(flow_record.src_ip)
                    if ips_success:
                        alert_event.action_taken = "BLOCKED"
                        # Update decision engine cache
                        decision_engine._blocked_ips_cache.add(flow_record.src_ip)

                # Persist to SQLite DB & WebSocket broadcast (sync to async helper loop)
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    async def save_and_notify():
                        async with _db_conn.AsyncSessionLocal() as db:
                            await crud.create_alert(db, alert_event.to_dict())
                            if alert_event.action_taken == "BLOCKED":
                                await crud.block_ip_db(
                                    db,
                                    ip=alert_event.src_ip,
                                    reason=f"Auto-blocked: {alert_event.attack_type}",
                                    alert_id=alert_event.alert_id,
                                    duration_seconds=ips_module.auto_unblock_after,
                                    blocked_by="system",
                                )
                        await ws_manager.broadcast("new_alert", alert_event.to_dict())

                    loop.run_until_complete(save_and_notify())
                    loop.close()
                except Exception as e:
                    logger.error(f"Error persisting alert event: {e}")

        except queue.Empty:
            pass

        # 3. Timeout Cleanup (every 30s)
        if (current_time - last_cleanup) >= 30.0:
            flow_aggregator.cleanup_timeouts(now=current_time)
            last_cleanup = current_time

        # 4. Traffic Stats Gathering (every 10s)
        if (current_time - last_stats_collect) >= 10.0:
            dt = current_time - last_stats_collect
            pps = float(packet_counter) / dt
            bps = float(bytes_counter) / dt
            packet_counter = 0
            bytes_counter = 0
            last_stats_collect = current_time

            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                async def save_traffic():
                    async with _db_conn.AsyncSessionLocal() as db:
                        stat = await crud.add_traffic_stat(db, packets_per_sec=pps, bytes_per_sec=bps, timestamp=current_time)
                        await ws_manager.broadcast("traffic_stats", stat.to_dict())

                loop.run_until_complete(save_traffic())
                loop.close()
            except Exception as e:
                logger.debug(f"Error recording traffic stats: {e}")

    logger.info("Processing worker thread exiting.")


def run_app(enable_capture: bool = True):
    """Main orchestrator function."""
    config = get_config()

    # Logging setup
    log_level = getattr(logging, config.get("general", "log_level", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    logger.info("=== Starting SAGEDRAL-ML NIDPS System ===")

    # Shared Queues
    packet_queue = queue.Queue(maxsize=config.get("capture", "queue_maxsize", 10000))
    flow_queue = queue.Queue(maxsize=10000)

    # Core Components
    flow_aggregator = FlowAggregator(flow_queue, config.get("feature_extraction", {}))
    signature_engine = SignatureEngine(
        disabled_rules=config.get("signature", "disabled_rules", []),
        custom_rules_file=config.get("signature", "custom_rules_file", ""),
    )
    ml_engine = MLEngine(
        model_dir=config.get("ml", "model_dir", "/var/lib/sagedral-ml/models"),
        anomaly_threshold=config.get("ml", "anomaly_threshold", 0.7),
        classifier_threshold=config.get("ml", "classifier_threshold", 0.6),
        enabled=config.get("ml", "enabled", True),
    )
    decision_engine = DecisionEngine(
        alert_threshold=config.get("decision", "alert_threshold", 0.5),
        block_threshold=config.get("decision", "block_threshold", 0.7),
        weight_signature=config.get("decision", "weight_signature", 0.4),
        weight_ml=config.get("decision", "weight_ml", 0.6),
        dedup_window=config.get("decision", "dedup_window", 300),
    )
    ips_module = IPSModule(
        enabled=config.get("ips", "enabled", True),
        preferred_backend=config.get("ips", "preferred_backend", "nftables"),
        whitelist=config.get("ips", "whitelist", []),
        auto_unblock_after=config.get("ips", "auto_unblock_after", 3600),
    )

    # Inject instances into API routers for endpoints
    blocked_ips.router.ips_module = ips_module
    model_router.router.ml_engine = ml_engine

    # Worker Thread
    worker_thread = threading.Thread(
        target=processing_worker,
        args=(packet_queue, flow_queue, flow_aggregator, signature_engine, ml_engine, decision_engine, ips_module),
        daemon=True,
    )
    worker_thread.start()

    # Capture Component
    sniffer = None
    if enable_capture:
        interface = config.get("capture", "interface", "eth0")
        sniffer = PacketCapture(
            interface=interface,
            packet_queue=packet_queue,
            bpf_filter=config.get("capture", "bpf_filter", ""),
            promiscuous=config.get("capture", "promiscuous", True),
        )
        try:
            sniffer.start()
        except Exception as e:
            logger.error(f"Could not start PacketCapture: {e}")

    # Shutdown signal handlers
    def handle_signal(sig, frame):
        logger.info("Signal received: shutting down SAGEDRAL-ML...")
        stop_event.set()
        if sniffer and sniffer.is_running:
            sniffer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Start FastAPI ASGI server in main thread
    api_host = config.get("api", "host", "0.0.0.0")
    api_port = config.get("api", "port", 8000)
    logger.info(f"Starting FastAPI Web Server & Dashboard at http://{api_host}:{api_port}")
    uvicorn.run(app, host=api_host, port=api_port, log_level="warning")


if __name__ == "__main__":
    run_app()
