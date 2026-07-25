#!/usr/bin/env python3
"""
vm_side_monitor.py — BackBox VM side: real-time monitoring dashboard for attack tests.

USAGE (in BackBox VM terminal, SAGEDRAL-ML ALREADY RUNNING):
    sudo python3 scripts/testing/vm_side_monitor.py          # refresh every 2s
    sudo python3 scripts/testing/vm_side_monitor.py --i 5    # refresh every 5s

Shows in one view, every refresh:
    • SAGEDRAL-ML service status (running? uptime?)
    • Sniffer interface + packet/flow counts (via CLI + API fallback)
    • ML Model Loaded, version, thresholds
    • nftables blocklist contents / count / LAST 5 blocked fake IPs added
    • Last 10 Alerts from DB (attack_class, src_ip, score, dst_port)
    • Total bytes/packets over time

Use this WHILE running spoofed_* attack scripts from Windows host to see
live detection and auto-block in action.
"""
import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

DB_PATH = "/var/lib/sagedral-ml/sagedral.db"
CONFIG_PATH = "/etc/sagedral/config.toml"


def run(cmd, timeout=10, default=""):
    try:
        return subprocess.run(
            cmd, shell=True, timeout=timeout,
            capture_output=True, text=True,
        ).stdout.strip()
    except Exception:
        return default


def section(title):
    cols = shutil.get_terminal_size((100, 40)).columns
    sep = "=" * cols
    print(f"\033[1;36m{sep}\033[0m")
    print(f"\033[1;36m  {title}\033[0m")
    print(f"\033[1;36m{sep}\033[0m")


def kv(k, v):
    print(f"  \033[1;37m{k:<30}\033[0m : {v}")


def check_service():
    section("1. SAGEDRAL-ML SERVICE")
    out = run("systemctl is-active sagedral-ml 2>&1 || true").strip()
    if not out:
        out = "unknown (systemctl missing)"
    kv("Active State", out)
    kv("PID (sagedral-ml main)", run("pgrep -af 'sagedral-ml start' | head -1 | awk '{print $1}'") or "-")
    kv("Uptime", run("systemctl show sagedral-ml -p ActiveEnterTimestamp --value 2>/dev/null || echo '-'"))


def check_sniffer_and_model():
    section("2. SNIFFER + ML MODEL")
    # Best effort via CLI (most accurate)
    status_raw = run("sagedral-ml status 2>&1 || true")
    print("  [sagedral-ml status]:")
    for line in status_raw.splitlines()[:10]:
        print(f"    {line}")
    print()
    model = run("sagedral-ml model info 2>&1 || true")
    print("  [sagedral-ml model info]:")
    for line in model.splitlines()[:8]:
        print(f"    {line}")


def check_nftables_blocklist():
    section("3. NFTABLES BLOCKLIST (auto-blocked FAKE spoofed IPs)")
    set_exists = run("nft list set inet sagedral blocklist 2>&1 | head -5 || echo ''")
    if not set_exists:
        print("  \033[1;33m[!] nftables set inet sagedral blocklist not found\033[0m")
        return
    entries = run("nft -j list set inet sagedral blocklist 2>&1 || true")
    total = 0
    ips = []
    try:
        j = json.loads(entries)
        for nft_obj in j.get("nftables", []):
            if "set" in nft_obj and nft_obj["set"].get("name") == "blocklist":
                elems = nft_obj["set"].get("elem", [])
                for e in elems:
                    if isinstance(e, str):
                        ips.append(e)
                    elif isinstance(e, dict) and "prefix" in e:
                        ips.append(e["prefix"]["addr"])
                total = len(ips)
    except Exception:
        flat = run("nft list set inet sagedral blocklist 2>&1 || true")
        for tok in flat.replace("{", " ").replace("}", " ").replace(",", " ").split():
            if tok.count(".") == 3:
                ips.append(tok)
        total = len(ips)
    kv("Total Blocked IPs", f"\033[1;31m{total}\033[0m")
    if ips:
        last = ips[-10:]
        print(f"  \033[1;31mLast {len(last)} blocked IPs (all should be FAKE spoofed IPs, NOT your host):\033[0m")
        for ip in reversed(last):
            print(f"    • {ip}")
    else:
        print("  (no blocked IPs yet — run attack scripts from Windows host)")


def check_db_alerts():
    section("4. LAST 10 SECURITY ALERTS (from SQLite DB)")
    p = Path(DB_PATH)
    if not p.exists():
        print(f"  \033[1;33m[!] Database not yet created: {DB_PATH}\033[0m")
        print("     (will appear after first alert triggers)")
        return
    try:
        con = sqlite3.connect(str(p))
        cur = con.cursor()
        cur.execute(
            "SELECT id, created_at, source_ip, destination_port, attack_class,"
            " anomaly_score, classifier_score, flow_id FROM alerts ORDER BY id DESC LIMIT 10"
        )
        rows = cur.fetchall()
        con.close()
    except Exception as e:
        print(f"  \033[1;31m[ERROR] DB query: {e}\033[0m")
        return
    if not rows:
        print("  (no alerts yet — run spoofed attack scripts from Windows host)")
        return
    print(f"  {'ID':>4}  {'Time':<19}  {'Src IP':<17}  {'DP':<5}  {'Class':<12}  {'A-Score':>7}  {'C-Score':>7}")
    print("  " + "-" * 95)
    for r in rows:
        _id, ts, sip, dp, acls, ascore, cscore, fid = r
        acls_ok = acls or "-"
        sip_ok = sip or "-"
        print(f"  {_id:>4}  {str(ts or '')[:19]:<19}  {sip_ok:<17}  {str(dp or '-'):<5}  {acls_ok:<12}  "
              f"{(f'{ascore:.3f}' if ascore is not None else '-'):>7}  "
              f"{(f'{cscore:.3f}' if cscore is not None else '-'):>7}")


def main():
    if os.geteuid() != 0:
        print("[!] This script needs sudo to access nftables + /var/lib/sagedral-ml DB.")
        print("    Re-run with: sudo python3 scripts/testing/vm_side_monitor.py")
        sys.exit(2)
    parser = argparse.ArgumentParser()
    parser.add_argument("--i", type=float, default=2.0, help="Refresh interval seconds (default 2.0)")
    parser.add_argument("--once", action="store_true", help="Run once then exit (no loop)")
    args = parser.parse_args()

    cols = shutil.get_terminal_size((100, 40)).columns
    print("\033[2J\033[H", end="")
    print("\033[1;32m" + "=" * cols + "\033[0m")
    print("\033[1;32m" + "  SAGEDRAL-ML — VM-SIDE LIVE MONITOR for Spoofed-Attack Testing".center(cols) + "\033[0m")
    print("\033[1;32m" + "  Run this in BackBox VM WHILE spoofed_*.py scripts run on Windows host.".center(cols) + "\033[0m")
    print("\033[1;32m" + "=" * cols + "\033[0m")

    try:
        while True:
            print("\033[s", end="")
            try:
                check_service()
                check_sniffer_and_model()
                check_nftables_blocklist()
                check_db_alerts()
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                cols = shutil.get_terminal_size((100, 40)).columns
                print()
                print(f"\033[1;30m{('Last refresh: ' + ts + ' | Ctrl+C to stop | next in ' + str(args.i) + 's').rjust(cols)}\033[0m")
            except Exception as e:
                print(f"  \033[1;31m[MONITOR ERROR]: {e}\033[0m")
            if args.once:
                break
            time.sleep(args.i)
            print("\033[u", end="")
    except KeyboardInterrupt:
        print("\n[*] Monitor stopped.")


if __name__ == "__main__":
    main()
