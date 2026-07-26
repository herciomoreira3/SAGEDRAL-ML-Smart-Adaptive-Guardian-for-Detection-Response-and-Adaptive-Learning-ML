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
import ipaddress
import re
import subprocess
import os
import socket
from typing import List, Optional
import uvicorn

from sagedral_ml.config import get_config
from sagedral_ml.capture.sniffer import create_packet_capture
from sagedral_ml.features.extractor import FlowAggregator
from sagedral_ml.detection.signature_engine import SignatureEngine
from sagedral_ml.detection.ml_engine import MLEngine
from sagedral_ml.detection.decision_engine import DecisionEngine
from sagedral_ml.ips.response import (
    IPSModule,
    ConnectionRateLimiter,
    calculate_escalated_duration,
)
from sagedral_ml.ips.models import AlertEvent
import sagedral_ml.database.connection as _db_conn
from sagedral_ml.database import crud
from sagedral_ml.api.main import app
from sagedral_ml.api.websocket import ws_manager
from sagedral_ml.core.container import global_container
from sagedral_ml.integrations import (
    geoip_resolver,
    notification_manager,
    siem_exporter,
)
from sagedral_ml.observability import metrics

logger = logging.getLogger("sagedral_ml.main")

stop_event = threading.Event()


def _systemd_notify(message: str) -> bool:
    """Send sd_notify datagram without requiring python-systemd."""
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return False
    address = notify_socket
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as client:
            client.connect(address)
            client.sendall(message.encode("utf-8"))
        return True
    except Exception as exc:
        logger.debug("systemd notify failed: %s", exc)
        return False


def _systemd_watchdog_worker(stop_event_ref: threading.Event) -> None:
    watchdog_usec = int(os.environ.get("WATCHDOG_USEC", "0") or 0)
    interval = max(1.0, watchdog_usec / 2_000_000.0) if watchdog_usec else 30.0
    while not stop_event_ref.wait(interval):
        _systemd_notify("WATCHDOG=1")


def _auto_detect_capture_interface(explicit: Optional[str]) -> str:
    """Select the best default capture interface when user does not explicitly
    override capture.interface in config.toml.

    Heuristic (highest priority first):
      1. Explicit value from config — if operstate exists and is up/unknown.
      2. Any UP non-loopback interface whose IP is NOT on 10.0.2.0/24
         (the canonical VirtualBox NAT subnet) — this picks eth1/enp0s8
         Bridged interfaces over eth0 (10.0.2.15 NAT).
      3. Any UP, non-loopback, non-pointopoint interface with a global IPv4.
      4. Absolute last-resort fallback: "eth0".
    """
    if explicit:
        try:
            with open("/sys/class/net/" + explicit + "/operstate") as f:
                state = f.read().strip()
            if state in ("up", "unknown"):
                return explicit
            logger.warning(
                f"Explicit capture interface '{explicit}' operstate={state}; "
                "trying auto-detect instead."
            )
        except FileNotFoundError:
            logger.warning(
                f"Explicit capture interface '{explicit}' not in /sys/class/net; "
                "auto-detecting."
            )

    candidates: List[tuple] = []  # (prio, name)
    try:
        res = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=3,
        )
        for line in res.stdout.splitlines():
            toks = line.split()
            if len(toks) < 4:
                continue
            iface = toks[1].split("@", 1)[0]
            cidr = toks[3]
            ip_part = cidr.split("/", 1)[0]
            try:
                addr = ipaddress.IPv4Address(ip_part)
            except ValueError:
                continue
            if addr.is_loopback or addr.is_link_local:
                continue
            flags_path = f"/sys/class/net/{iface}/flags"
            iface_flags = 0
            try:
                with open(flags_path) as f:
                    iface_flags = int(f.read().strip(), 16)
            except Exception:
                pass
            # IFF_LOOPBACK=0x8 / IFF_POINTOPOINT=0x10 — skip these.
            skip_mask = 0x8 | 0x10
            if iface_flags & skip_mask:
                continue
            prio = 0
            # Penalize VirtualBox NAT subnet heavily.
            if addr in ipaddress.IPv4Network("10.0.2.0/24"):
                prio -= 100
            # Penalize container bridges.
            if iface.startswith(("docker", "veth", "br-", "virbr", "vnet", "lxc")):
                prio -= 50
            # Prefer classic bridged / physical naming conventions.
            if re.match(r"^(eth[1-9]|enp0s[8-9]|ens[0-9]+|wlan[0-9]+|wl[a-z0-9]+)$", iface):
                prio += 10
            if not addr.is_private:
                prio += 20
            candidates.append((prio, iface))
    except Exception as e:
        logger.debug(f"Could not enumerate interfaces for capture auto-detect: {e}")

    if candidates:
        candidates.sort(key=lambda x: (-x[0], x[1]))
        best = candidates[0][1]
        logger.info(f"Auto-detected capture interface: '{best}' (candidates: {candidates})")
        return best
    logger.warning("No valid capture interface found via auto-detect; falling back to 'eth0'.")
    return "eth0"


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
    config = get_config()
    batch_size = max(1, int(config.get("ml", "batch_size", 32) or 32))
    rate_limiter = ConnectionRateLimiter(
        maximum=int(config.get("ips", "rate_limit_connections", 100) or 100),
        window_seconds=int(
            config.get("ips", "rate_limit_window_seconds", 60) or 60
        ),
    )
    rate_limit_enabled = bool(
        config.get("ips", "rate_limit_enabled", False)
    )
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
            first_flow = flow_queue.get_nowait()
            flow_records = [first_flow]
            while len(flow_records) < batch_size:
                try:
                    flow_records.append(flow_queue.get_nowait())
                except queue.Empty:
                    break
            feature_vectors = []
            for flow_record in flow_records:
                vector = flow_record.to_feature_vector()
                vector["src_ip"] = flow_record.src_ip
                vector["dst_ip"] = flow_record.dst_ip
                feature_vectors.append(vector)
            ml_results = ml_engine.predict_batch(feature_vectors)

            for flow_record, feature_vector, ml_result in zip(
                flow_records, feature_vectors, ml_results
            ):
                sig_result = signature_engine.evaluate(feature_vector)
                decision = decision_engine.decide(
                    sig_result,
                    ml_result,
                    src_ip=flow_record.src_ip,
                    now=current_time,
                )
                if rate_limit_enabled and rate_limiter.record(
                    flow_record.src_ip, current_time
                ):
                    decision.is_threat = True
                    decision.action = "BLOCK"
                    decision.attack_type = "ConnectionRateLimit"
                    decision.severity = "HIGH"
                    decision.final_score = max(decision.final_score, 0.75)

                metrics.inc("sagedral_flows_total")
                if not (
                    decision.is_threat or decision.action in ("BLOCK", "ALERT")
                ):
                    continue
                country_name, country_code = geoip_resolver.country(
                    flow_record.src_ip
                )
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
                alert_data = alert_event.to_dict()
                alert_data["feature_vector"] = {
                    name: feature_vector.get(name, 0.0)
                    for name in ml_engine.feature_names
                }
                alert_data["src_country"] = country_name
                alert_data["src_country_code"] = country_code

                # IPS Firewall Execution
                if decision.action == "BLOCK":
                    ips_success = ips_module.block_ip(flow_record.src_ip)
                    if ips_success:
                        alert_event.action_taken = "BLOCKED"
                        alert_data["action_taken"] = "BLOCKED"
                        # Update decision engine cache
                        decision_engine._blocked_ips_cache.add(flow_record.src_ip)

                # Persist to SQLite DB & WebSocket broadcast (sync to async helper loop)
                try:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    async def save_and_notify():
                        async with _db_conn.AsyncSessionLocal() as db:
                            await crud.create_alert(db, alert_data)
                            if alert_event.action_taken == "BLOCKED":
                                duration = (
                                    int(
                                        config.get(
                                            "ips",
                                            "rate_limit_block_seconds",
                                            300,
                                        )
                                        or 300
                                    )
                                    if alert_event.attack_type
                                    == "ConnectionRateLimit"
                                    else ips_module.auto_unblock_after
                                )
                                if config.get(
                                    "ips", "strike_escalation_enabled", True
                                ):
                                    offense = await crud.record_ip_offense(
                                        db, alert_event.src_ip
                                    )
                                    duration = calculate_escalated_duration(
                                        duration, offense.strike_count
                                    )
                                await crud.block_ip_db(
                                    db,
                                    ip=alert_event.src_ip,
                                    reason=f"Auto-blocked: {alert_event.attack_type}",
                                    alert_id=alert_event.alert_id,
                                    duration_seconds=duration,
                                    blocked_by="system",
                                )
                        await ws_manager.broadcast("new_alert", alert_data)

                    loop.run_until_complete(save_and_notify())
                    loop.close()
                    metrics.inc(
                        "sagedral_alerts_total",
                        labels={
                            "severity": alert_event.severity,
                            "attack_type": alert_event.attack_type,
                        },
                    )
                    if alert_event.action_taken == "BLOCKED":
                        metrics.inc("sagedral_blocks_total")
                    siem_exporter.send(alert_data)
                    notification_manager.submit(alert_data)
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


def capture_thread_worker(
    interface: str,
    packet_queue: queue.Queue,
    bpf_filter: str,
    promiscuous: bool,
    stop_event_ref: threading.Event,
    backend: str = "scapy",
    watchdog_idle_seconds: int = 30,
):
    """Capture thread with auto-recovery watchdog (IMP-CAP-02)."""
    restart_count = 0
    sniffer = None

    while not stop_event_ref.is_set():
        sniffer = create_packet_capture(
            backend=backend,
            interface=interface,
            packet_queue=packet_queue,
            bpf_filter=bpf_filter,
            promiscuous=promiscuous,
        )
        try:
            sniffer.start()
            global_container.set_capture_module(sniffer)
            logger.info(f"Capture thread active on '{interface}' (restart #{restart_count})")

            while not stop_event_ref.is_set() and sniffer.is_running:
                time.sleep(1)
                stats = sniffer.get_stats()
                last_seen = stats.get("last_packet_seen_sec_ago")
                received = stats.get("packets_received", 0)
                if (
                    received > 0
                    and last_seen is not None
                    and last_seen > watchdog_idle_seconds
                ):
                    logger.warning(
                        "Capture watchdog: no packets for >%ss on interface '%s', restarting capture",
                        watchdog_idle_seconds,
                        interface,
                    )
                    sniffer.stop()
                    break
        except Exception as e:
            restart_count += 1
            logger.error(
                "Capture thread crashed (restart #%d), retry in 5s: %s",
                restart_count,
                e,
            )
        finally:
            if sniffer is not None and sniffer.is_running:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            global_container.set_capture_module(None)

        if not stop_event_ref.is_set():
            time.sleep(5)

    logger.info("Capture thread exiting.")


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
    stop_event.clear()

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
    ml_engine.configure_drift(
        int(config.get("ml", "drift_window_size", 100) or 100)
    )
    ml_predictor = ml_engine
    parallel_ml_engine = None
    detection_workers = max(
        1, int(config.get("performance", "detection_workers", 1) or 1)
    )
    if detection_workers > 1:
        try:
            from sagedral_ml.detection.parallel import MultiprocessMLEngine

            parallel_ml_engine = MultiprocessMLEngine(
                ml_engine, detection_workers
            )
            ml_predictor = parallel_ml_engine
            logger.info(
                "Multiprocess ML inference enabled with %d workers.",
                detection_workers,
            )
        except Exception as exc:
            logger.error(
                "Could not start multiprocess ML inference; using local engine: %s",
                exc,
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

    global_container.set_config(config)
    global_container.set_signature_engine(signature_engine)
    global_container.set_ml_engine(ml_engine)
    global_container.set_decision_engine(decision_engine)
    global_container.set_ips_module(ips_module)
    global_container.set_aggregator(flow_aggregator)

    async def _startup_reconcile():
        await _db_conn.init_db()
        async with _db_conn.AsyncSessionLocal() as db:
            rules_loaded = await signature_engine.load_rules_from_db(db)
            logger.info("Loaded %d custom signature rule(s) from database.", rules_loaded)
            await ips_module.reconcile_from_db(db)

    try:
        asyncio.run(_startup_reconcile())
    except Exception as e:
        logger.error(f"Startup reconcile/load-rules failed: {e}")

    # Worker Thread
    worker_thread = threading.Thread(
        target=processing_worker,
        args=(packet_queue, flow_queue, flow_aggregator, signature_engine, ml_predictor, decision_engine, ips_module),
        daemon=True,
    )
    worker_thread.start()

    # Capture Component (watchdog thread with auto-recovery)
    capture_thread = None
    if enable_capture:
        explicit_iface = config.get("capture", "interface", None)
        interface = _auto_detect_capture_interface(explicit_iface)
        logger.info(f"Starting packet capture on interface '{interface}' (explicit={explicit_iface!r})")
        capture_thread = threading.Thread(
            target=capture_thread_worker,
            args=(
                interface,
                packet_queue,
                config.get("capture", "bpf_filter", ""),
                config.get("capture", "promiscuous", True),
                stop_event,
                config.get("capture", "backend", "scapy"),
                int(
                    config.get("capture", "watchdog_idle_seconds", 30) or 30
                ),
            ),
            daemon=True,
            name="sagedral-capture",
        )
        capture_thread.start()

    # Shutdown signal handlers
    def handle_signal(sig, frame):
        logger.info("Signal received: shutting down SAGEDRAL-ML...")
        stop_event.set()
        capture_mod = global_container.capture_module
        if capture_mod and capture_mod.is_running:
            capture_mod.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Start FastAPI ASGI server in main thread
    api_host = config.get("api", "host", "0.0.0.0")
    api_port = config.get("api", "port", 8000)
    logger.info(f"Starting FastAPI Web Server & Dashboard at http://{api_host}:{api_port}")
    watchdog_thread = threading.Thread(
        target=_systemd_watchdog_worker,
        args=(stop_event,),
        daemon=True,
        name="sagedral-systemd-watchdog",
    )
    watchdog_thread.start()
    _systemd_notify("READY=1\nSTATUS=SAGEDRAL-ML API and detection pipeline active")
    try:
        uvicorn.run(app, host=api_host, port=api_port, log_level="warning")
    finally:
        stop_event.set()
        _systemd_notify("STOPPING=1")
        worker_thread.join(timeout=10)
        if capture_thread is not None:
            capture_thread.join(timeout=10)
        if parallel_ml_engine is not None:
            parallel_ml_engine.close()
        notification_manager.close()
        siem_exporter.close()
        geoip_resolver.close()


if __name__ == "__main__":
    run_app()
