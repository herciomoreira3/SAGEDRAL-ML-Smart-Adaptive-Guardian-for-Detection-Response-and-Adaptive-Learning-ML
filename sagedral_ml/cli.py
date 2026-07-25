"""
Click CLI Command Line Interface for SAGEDRAL-ML tool.
"""

import sagedral_ml
import os
import sys
import json
import click
import requests
from sagedral_ml import __version__
from sagedral_ml.config import get_config, load_config, generate_default_toml_string, DEFAULT_CONFIG_PATH
from sagedral_ml.ips.response import validate_ip


API_BASE = "http://localhost:8000/api/v1"


@click.group()
@click.version_option(__version__, message="SAGEDRAL-ML version %(version)s")
def main():
    """SAGEDRAL-ML — Smart Adaptive Guardian for Detection, Response, and Adaptive Learning - ML NIDPS System."""
    pass


# ================= SERVICE COMMANDS =================

@main.command()
@click.option("--daemon/--no-daemon", default=False, help="Run as background daemon process")
@click.option("--no-capture", is_flag=True, help="Disable network packet capture (for development/testing)")
def start(daemon, no_capture):
    """Start SAGEDRAL-ML NIDPS service."""
    from sagedral_ml.main import run_app

    click.echo("Starting SAGEDRAL-ML system...")
    if daemon:
        click.echo("Daemon mode activated.")
    run_app(enable_capture=not no_capture)


@main.command()
def stop():
    """Stop running SAGEDRAL-ML service."""
    click.echo("Stopping SAGEDRAL-ML service...")
    # Send SIGTERM to process if running
    os.system("pkill -f 'sagedral-ml start' || true")
    click.echo("Stop command issued.")


@main.command()
def status():
    """Check running status of SAGEDRAL-ML service."""
    try:
        r = requests.get(f"{API_BASE}/status", timeout=2)
        if r.status_code == 200:
            data = r.json()
            click.secho("SAGEDRAL-ML Service: RUNNING", fg="green", bold=True)
            click.echo(f"  Interface:         {data.get('interface')}")
            click.echo(f"  Uptime:            {data.get('uptime_seconds')}s")
            click.echo(f"  Active Blocked IPs:{data.get('blocked_ips_count')}")
            click.echo(f"  ML Model Loaded:   {data.get('ml_model_loaded')}")
            return
    except Exception:
        pass
    click.secho("SAGEDRAL-ML Service: STOPPED / UNREACHABLE", fg="red", bold=True)


@main.command()
def restart():
    """Restart SAGEDRAL-ML service."""
    stop.callback()
    start.callback(daemon=True, no_capture=False)


# ================= CONFIG COMMANDS =================

@main.group()
def config():
    """Configuration management subcommands."""
    pass


@config.command("show")
def config_show():
    """Show current active configuration."""
    cfg = get_config()
    click.echo(json.dumps(cfg.to_dict(), indent=2))


@config.command("template")
def config_template():
    """Generate default config.toml template to stdout."""
    click.echo(generate_default_toml_string())


@config.command("validate")
def config_validate():
    """Validate configuration file."""
    cfg = get_config()
    errors = cfg.validate()
    if errors:
        click.secho("Configuration Validation FAILED:", fg="red", bold=True)
        for err in errors:
            click.echo(f"  - {err}")
        sys.exit(1)
    else:
        click.secho("Configuration is VALID.", fg="green", bold=True)


# ================= IP MANAGEMENT COMMANDS =================

@main.command()
@click.argument("ip")
@click.option("--duration", default=3600, help="Block duration in seconds (0 = permanent)")
@click.option("--reason", default="Manual CLI block", help="Reason for block")
def block(ip, duration, reason):
    """Manually block an IP address in firewall."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        click.secho(f"Error: {e}", fg="red")
        return

    try:
        r = requests.post(f"{API_BASE}/blocked-ips", json={
            "ip": clean_ip, "reason": reason, "duration_seconds": duration
        }, timeout=3)
        if r.status_code == 200:
            click.secho(f"Successfully blocked IP {clean_ip}", fg="green")
        else:
            click.secho(f"Failed: {r.json().get('detail', r.text)}", fg="red")
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


@main.command()
@click.argument("ip")
def unblock(ip):
    """Manually unblock an IP address from firewall."""
    try:
        clean_ip = validate_ip(ip)
    except ValueError as e:
        click.secho(f"Error: {e}", fg="red")
        return

    try:
        r = requests.delete(f"{API_BASE}/blocked-ips/{clean_ip}", timeout=3)
        if r.status_code == 200:
            click.secho(f"Successfully unblocked IP {clean_ip}", fg="green")
        else:
            click.secho(f"Failed: {r.json().get('detail', r.text)}", fg="red")
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


# ================= ALERTS COMMANDS =================

@main.group()
def alerts():
    """Alert management subcommands."""
    pass


@alerts.command("list")
@click.option("--limit", default=20, help="Number of alerts to display")
def alerts_list(limit):
    """List recent security alerts."""
    try:
        r = requests.get(f"{API_BASE}/alerts?limit={limit}", timeout=3)
        if r.status_code == 200:
            data = r.json().get("data", [])
            if not data:
                click.echo("No alerts recorded.")
                return

            click.echo(f"{'TIME':<20} {'SRC IP':<16} {'DST IP':<16} {'ATTACK TYPE':<15} {'SEVERITY':<10} {'ACTION':<10}")
            click.echo("-" * 90)
            for a in data:
                import datetime
                t_str = datetime.datetime.fromtimestamp(a["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                click.echo(f"{t_str:<20} {a['src_ip']:<16} {a['dst_ip']:<16} {a['attack_type']:<15} {a['severity']:<10} {a['action_taken']:<10}")
            return
    except Exception as e:
        click.secho(f"API request failed: {e}", fg="red")


# ================= MODEL COMMANDS =================

@main.group()
def model():
    """ML model management subcommands."""
    pass


@model.command("init")
@click.option("--force", is_flag=True, help="Overwrite existing model files with fresh fallback models")
@click.option("--model-dir", default=None, help="Override model directory path (default: from config)")
def model_init(force, model_dir):
    """Initialize / regenerate ML detection models (installs fallback models if none exist)."""
    cfg = get_config()
    resolved_dir = model_dir if model_dir else cfg.get("ml", "model_dir", "/var/lib/sagedral-ml/models")
    enabled = cfg.get("ml", "enabled", True)
    anomaly_threshold = float(cfg.get("ml", "anomaly_threshold", 0.7))
    classifier_threshold = float(cfg.get("ml", "classifier_threshold", 0.6))

    if force:
        for fname in ("anomaly_detector.pkl", "attack_classifier.pkl", "feature_names.json"):
            fp = os.path.join(resolved_dir, fname)
            if os.path.exists(fp):
                try:
                    os.remove(fp)
                except OSError as e:
                    click.secho(f"Warning: could not remove {fp}: {e}", fg="yellow")

    click.echo(f"Initializing ML models in {resolved_dir} ...")
    from sagedral_ml.detection.ml_engine import MLEngine
    engine = MLEngine(
        model_dir=resolved_dir,
        anomaly_threshold=anomaly_threshold,
        classifier_threshold=classifier_threshold,
        enabled=enabled,
    )

    if engine.model_loaded:
        click.secho(f"[OK] ML models ready. loaded={engine.model_loaded} version={engine.version}", fg="green", bold=True)
        click.echo(f"  anomaly_model.pkl : {os.path.exists(os.path.join(resolved_dir, 'anomaly_detector.pkl'))}")
        click.echo(f"  attack_classifier : {os.path.exists(os.path.join(resolved_dir, 'attack_classifier.pkl'))}")
        if "rulebased" in engine.version:
            click.secho("  Note: rule-based fallback active. Install lightgbm+scikit-learn for trained models.", fg="yellow")
        elif "fallback" in engine.version:
            click.secho("  Note: synthetic data fallback active. Train on real dataset for production accuracy.", fg="yellow")
        sys.exit(0)
    else:
        click.secho("[FAILED] Could not initialize ML models. Check logs above.", fg="red", bold=True)
        sys.exit(1)


@model.command("info")
def model_info():
    """Show details of loaded ML models."""
    # Offline: instantiate local engine to inspect files; online: hit API if service is running
    offline_info = None
    try:
        cfg = get_config()
        resolved_dir = cfg.get("ml", "model_dir", "/var/lib/sagedral-ml/models")
        from sagedral_ml.detection.ml_engine import MLEngine
        engine = MLEngine(
            model_dir=resolved_dir,
            anomaly_threshold=float(cfg.get("ml", "anomaly_threshold", 0.7)),
            classifier_threshold=float(cfg.get("ml", "classifier_threshold", 0.6)),
            enabled=cfg.get("ml", "enabled", True),
        )
        offline_info = {
            "enabled": cfg.get("ml", "enabled", True),
            "loaded": engine.model_loaded,
            "model_dir": resolved_dir,
            "model_version": engine.version,
            "local": True,
        }
    except Exception as e:
        offline_info = {"error": str(e), "local": True}

    try:
        r = requests.get(f"{API_BASE}/model/info", timeout=2)
        if r.status_code == 200:
            online = r.json()
            online["local"] = False
            click.echo(json.dumps(online, indent=2))
            return
    except Exception:
        pass

    if offline_info is not None:
        click.echo(json.dumps(offline_info, indent=2))
    else:
        click.secho("Service not running and local engine unavailable.", fg="red")


# ================= SELF-TEST COMMANDS (Sniffer + Capture Debug WSL) =================

@main.group()
def selftest():
    """Self-test diagnostics: capture sniffer, models, IPS firewalls."""
    pass


def _cli_detect_primary_iface_and_ip():
    import re, subprocess
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True)
        ifaces = []
        for line in out.splitlines():
            m = re.search(r"^\d+:\s+(\S+?)(@\S+)?\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", line)
            if not m:
                continue
            iface, ip, cidr = m.group(1), m.group(3), int(m.group(4))
            if iface == "lo":
                continue
            prio = 0 if iface == "wifi0" else (1 if iface == "eth0" else 2)
            ifaces.append((prio, iface, ip, cidr))
        ifaces.sort()
        return ifaces[0][1], ifaces[0][2], ifaces[0][3]
    except Exception:
        return "any", "127.0.0.1", 8


@selftest.command("capture")
@click.option("--iface", default=None, help="Override interface to test (default: auto detect wifi0)")
@click.option("--duration", type=int, default=8, help="Seconds to run capture probe")
@click.option("--external-ip", default="8.8.8.8", help="External dst IP to force packet exit via real NIC")
def selftest_capture(iface, duration, external_ip):
    """
    PROOF sniffer SAGEDRAL & interface OK.
    Teknik: Kirim 80+ UDP + TCP + ICMP ke EXTERNAL IP (8.8.8.8) melalui default route wifi0.
    Paket KELUAR interface BENAR → AF_PACKET menangkap → tcpdump/scapy BISA baca.
    Output: Packet count per interface + rekomendasi interface capture terbaik.
    """
    import random, socket, subprocess, threading, tempfile, time
    if os.geteuid() != 0:
        click.secho("[FAIL] SELFTEST CAPTURE BUTUH ROOT. Jalankan sudo.", fg="red", bold=True)
        sys.exit(2)

    iface_auto, primary_ip, cidr = _cli_detect_primary_iface_and_ip()
    iface = iface or iface_auto

    click.secho(f"=== SAGEDRAL SELFTEST: CAPTURE INTERFACE ===", bold=True)
    click.echo(f"  Primary interface  : {iface} (IP={primary_ip})")
    click.echo(f"  External dst IP    : {external_ip} (paket keluar via real NIC WiFi0)")
    click.echo(f"  Duration           : {duration}s")
    click.echo(f"  Teknik             : UDP/TCP/ICMP keluar via default route → AF_PACKET capture.")

    # --- Start tcpdump di beberapa interface parallel ---
    candidates = ["any", iface, "lo"]
    candidates = list(dict.fromkeys(candidates))
    procs = {}
    outfiles = {}
    try:
        for i in candidates:
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=f".cap{i}.txt")
            tf.close()
            outfiles[i] = tf.name
            try:
                p = subprocess.Popen(
                    ["tcpdump", "-ni", i, "-c", "1500", "-Q", "out",
                     f"(udp or tcp or icmp) and dst host {external_ip}"],
                    stdout=open(tf.name, "w", encoding="utf-8"),
                    stderr=subprocess.DEVNULL,
                )
                procs[i] = p
            except Exception as e:
                click.secho(f"  [!] tcpdump gagal iface {i}: {e}", fg="yellow")
        click.echo(f"\n[*] Tunggu 1.5d tcpdump ready...")
        time.sleep(1.5)

        # --- Kirim 80+ probe packets ke EXTERNAL IP ---
        def _send():
            # 50 UDP random payload ke external_ip:53
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                for _ in range(50):
                    try:
                        payload = bytes([random.randint(0,255) for _ in range(random.randint(64, 512))])
                        u.sendto(payload, (external_ip, random.choice([53, 5353, 123, 67, 80, 443])))
                    except Exception:
                        pass
                    time.sleep(0.001)
                u.close()
            except Exception:
                pass
            # 25 TCP SYN (non-blocking connect_ex)
            for _ in range(25):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.03)
                    s.setblocking(False)
                    try: s.connect_ex((external_ip, random.choice([80,443,22,53,8080])))
                    except Exception: pass
                    try: s.close()
                    except Exception: pass
                except Exception:
                    pass
                time.sleep(0.005)
            # 10 ICMP ping -c 1
            try:
                for _ in range(10):
                    subprocess.run(["ping", "-c", "1", "-W", "1", external_ip],
                                   capture_output=True, timeout=3, check=False)
            except Exception:
                pass
            click.echo(f"\n  [SEND OK] 85+ probe packets keluar menuju {external_ip} via wifi0 default route.")
        t_send = threading.Thread(target=_send, daemon=True)
        t_send.start()
        t_send.join(timeout=duration)

        # --- Tunggu sisa duration, kill tcpdump ---
        remaining = max(1, duration - int(time.time() - (time.time())))
        # simpler: tunggu sisa 2.5 detik
        time.sleep(2.5)
    finally:
        for i, p in procs.items():
            try:
                p.terminate()
                try: p.wait(timeout=2)
                except Exception: p.kill()
            except Exception:
                pass

    # --- Count packets captured ---
    click.echo(f"\n{'─'*60}")
    click.secho("HASIL: Packet COUNT tertangkap per interface (outgoing ke %s):\n" % external_ip, bold=True)
    click.echo(f"  {'Interface':15s}  Packets  Status")
    click.echo(f"  {'─'*15}  ───────  ───────────")
    best = ("any", 0)
    scored = []
    for i, fpath in outfiles.items():
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                lines = [ln for ln in f.readlines() if ln.strip() and "listening on" not in ln and "tcpdump:" not in ln]
            count = len(lines)
        except Exception:
            count = -1
        mark = "✅ CAPTURE OK (>20)" if count >= 20 else ("⚠️  (<20)" if count > 0 else "❌ TIDAK ADA PAKET")
        click.echo(f"  {i:15s}  {count:>7d}  {mark}")
        scored.append((i, count))
        try: os.unlink(fpath)
        except Exception: pass

    # Best iface = highest count; prefer specific over 'any'
    scored_sorted = sorted(scored, key=lambda x: (-x[1], 0 if x[0]!="any" else 1))
    best_name, best_cnt = scored_sorted[0]
    click.echo(f"\n[REKOMENDASI] capture.interface = {best_name}  (packets={best_cnt})")

    if best_cnt < 20:
        click.secho("\n[WARN] Packet capture < 20! WSL network mungkin firewall luar blokir atau route tidak ke wifi0.", fg="yellow", bold=True)
        click.echo("   Solusi:")
        click.echo("     1. Pastikan Windows host Anda terkoneksi Internet aktif (WiFi/Hotspot HP).")
        click.echo("     2. Coba ganti --external-ip=1.1.1.1 / --external-ip=208.67.222.222.")
        click.echo("     3. Pastikan WSL mirror mode auto-proxy TIDAK memblock paket UDP/ICMP keluar.")
        click.echo("     4. Jika tetap 0 → firewall Windows/antivirus blocking. Untuk test sementara gunakan inject_flow_simulator.py.")
        sys.exit(3)
    else:
        click.secho(f"\n[✅] SNIFFER SAGEDRAL BISA MENANGKAP PAKET di interface {best_name}.", fg="green", bold=True)
        click.echo("   Sekarang Anda bisa jalankan attack script yang menargetkan IP EXTERNAL + SNAT spoof src IP.")
        click.echo(f"   Silakan lanjut ke: sudo python3 sagedral_full_test_wsl.py --iface {best_name}")
        sys.exit(0)


@selftest.command("sniffer-status")
def selftest_sniffer_status():
    """Query live packet count & capture stats dari SAGEDRAL API (service harus jalan)."""
    try:
        r = requests.get(f"{API_BASE}/status", timeout=2.5)
        if r.status_code != 200:
            click.secho("Service OFFLINE. Start dulu: sagedral-ml start", fg="red")
            sys.exit(1)
        data = r.json()
        click.secho("Live capture status:", bold=True)
        for k in ("interface", "uptime_seconds", "blocked_ips_count", "ml_model_loaded",
                  "packets_captured_total", "flows_processed", "alerts_total_count"):
            if k in data:
                click.echo(f"  {k:35s} = {data[k]}")
    except Exception as e:
        click.secho(f"Gagal query API: {e}. Jalankan service dulu: sagedral-ml start", fg="red")
        sys.exit(1)

