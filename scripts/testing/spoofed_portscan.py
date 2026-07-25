#!/usr/bin/env python3
"""
spoofed_portscan.py — Port Scanner with SPOOFED Source IP per connection.
Runs on: Windows (Python + Npcap) / WSL / Linux attacker root.

ATTACKER SIDE (Windows host):
    sudo python3 scripts/testing/spoofed_portscan.py \
        --target 192.168.1.123 \
        --ports top100 \
        --interval 0.02

SAFETY: EVERY SYN packet uses a DIFFERENT random spoofed source IP,
so your real Windows host IP NEVER appears as attacker -> no auto-block of host.
SAGEDRAL-ML will see PortScan signature (high syn_flag_count + dst_port spread)
and block the FAKE IPs — not yours.
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("[FATAL] scapy not installed. Run: pip install scapy")
    print("   Windows also requires Npcap from https://npcap.com/")
    sys.exit(1)

conf.verb = 0


TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1434, 1720, 1723, 1755, 1900, 2000, 2001,
    2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]


def _random_spoofed_src_ip() -> str:
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 192):
            continue
        b = random.randint(0, 255)
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        return f"{a}.{b}.{random.randint(0,255)}.{random.randint(1,254)}"


def port_scan(target_ip: str, ports, interval_s: float) -> None:
    print("=" * 70)
    print(f"  SPOOFED PORT SCAN — Target: {target_ip}")
    print(f"  Ports: {len(ports)} ports | Inter-packet: {interval_s}s")
    print(f"  SAFETY: EACH SYN uses a NEW random spoofed source IP.")
    print(f"          Your real host IP is NEVER the scanner source ✅")
    print("=" * 70)
    time.sleep(2)

    sent = 0
    try:
        for port in ports:
            src = _random_spoofed_src_ip()
            pkt = IP(src=src, dst=target_ip) / TCP(
                sport=random.randint(1024, 65535),
                dport=port,
                flags="S",
                seq=random.randint(1000, 0xFFFFFFFF),
                window=65535,
            )
            send(pkt, verbose=0)
            sent += 1
            if sent % 20 == 0:
                print(f"  [+] Probed {sent}/{len(ports)} ports | last dst port={port} src_ip={src}")
            time.sleep(interval_s)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")

    print("-" * 70)
    print(f"[DONE] Sent {sent} SYN probes (Port Scan signature)")
    print(f"       -> SAGEDRAL-ML feature 'syn_flag_count' + dst_port spread")
    print(f"          should classify this traffic as attack class PortScan")
    print(f"\n👉 Verify on BackBox VM:")
    print(f"   CLI : sagedral-ml alerts list --limit 30")
    print(f"   CLI : sudo nft list set inet sagedral blocklist")
    print(f"   Web : Dashboard -> Alerts + Blocked IPs tabs")


def _parse_port_spec(spec: str):
    spec = spec.strip().lower()
    if spec == "top100":
        return TOP_100_PORTS
    if spec == "all":
        return list(range(1, 65536))
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.extend(range(int(lo), int(hi) + 1))
        else:
            out.append(int(part))
    return sorted(set(out))


def main():
    p = argparse.ArgumentParser(description="Port scan with SPOOFED src IP per probe (no real IP leaks)")
    p.add_argument("--target", "-t", required=True, help="Target BackBox VM IP (bridged)")
    p.add_argument("--ports", default="top100", help="Port spec: 'top100', '1-1000', '22,80,443,3306,8080', 'all' (default: top100)")
    p.add_argument("--interval", type=float, default=0.02, help="Seconds between probes (default: 0.02 = fast, ~50/s)")
    args = p.parse_args()
    ports = _parse_port_spec(args.ports)
    if not ports:
        print("FATAL: no ports to scan.")
        sys.exit(2)
    print(f"[+] Port list prepared: {len(ports)} unique ports.")
    port_scan(args.target, ports, args.interval)


if __name__ == "__main__":
    main()
