#!/usr/bin/env python3
"""
spoofed_brute_force.py — SSH/HTTP brute-force pattern generator with SPOOFED source IPs.

This does NOT actually try to crack passwords (illegal/unethical on systems you don't own).
Instead, it GENERATES the EXACT NETWORK SIGNATURE of a brute force attack:
  - Bursts of TCP SYN + full 3-way handshake pattern
  - Repeated SYN -> RST/SYN-ACK loops to common auth ports (22/SSH, 3389/RDP, 21/FTP, 8080/HTTP)
  - High flow_packets_per_sec concentrated on auth ports

SAFETY: 100% SPOOFED source IPs — your Windows real IP is NEVER used.

ATTACKER SIDE (Windows/WSL root):
    sudo python3 scripts/testing/spoofed_brute_force.py \
        --target 192.168.1.123 \
        --ports 22,3389,8080 \
        --duration 20 \
        --attempts-per-port 200
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, send, conf
except ImportError:
    print("[FATAL] scapy not installed. Run: pip install scapy  (+ Npcap on Windows)")
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


def brute_force_signature(target_ip: str, ports, attempts_per_port: int, duration: int) -> None:
    print("=" * 70)
    print(f"  SPOOFED BRUTE FORCE SIGNATURE — Target: {target_ip}:{ports}")
    print(f"  Attempts/port: {attempts_per_port} | Duration cap: {duration}s")
    print(f"  SAFETY: All spoofed src IPs — real host IP never used ✅")
    print("=" * 70)
    print("[!] NOTE: This generates a BRUTE FORCE network SIGNATURE only.")
    print("    No actual credential guessing is performed (legal / ethical).")
    print()
    time.sleep(2)

    end_ts = time.time() + duration
    sent = 0
    last_report = time.time()

    try:
        for port in ports:
            for _ in range(attempts_per_port):
                if time.time() >= end_ts:
                    break
                src = _rand_spoofed_src()
                sport = random.randint(1024, 65535)
                seq0 = random.randint(1000, 0xFFFFFFFF)

                # SYN (step 1)
                pkt_syn = IP(src=src, dst=target_ip) / TCP(
                    sport=sport, dport=port, flags="S", seq=seq0, window=65535
                )
                send(pkt_syn, verbose=0)
                sent += 1

                # Immediately follow with a RST (simulates "client gives up after
                # seeing banner / bad password" pattern observed in real brute force)
                pkt_rst = IP(src=src, dst=target_ip) / TCP(
                    sport=sport, dport=port, flags="R", seq=seq0 + 1, window=0
                )
                send(pkt_rst, verbose=0)
                sent += 1

                # Very short burst between attempts (real brute force = rapid)
                time.sleep(random.uniform(0.005, 0.03))

                if time.time() - last_report >= 2.0:
                    print(f"  [+] Port {port}: ~{sent} packets | src={src}")
                    last_report = time.time()
            if time.time() >= end_ts:
                break

    except KeyboardInterrupt:
        print("\n[!] Interrupted.")

    print("-" * 70)
    print(f"[DONE] Sent {sent} packets (brute force signature).")
    print(f"       High rst_flag_count + dst_port on auth ports")
    print(f"       -> SAGEDRAL-ML classifier should fire: attack class BruteForce")
    print(f"\n👉 Verify on BackBox VM:")
    print(f"   CLI : sagedral-ml alerts list --limit 30")
    print(f"   Web : Dashboard Alerts tab (filter by BruteForce)")


def _parse_ports(s: str):
    out = []
    for p in s.split(","):
        p = p.strip()
        if p:
            out.append(int(p))
    return out or [22]


def main():
    p = argparse.ArgumentParser(description="Generate SSH/RDP brute force network signature with SPOOFED src IPs")
    p.add_argument("--target", "-t", required=True, help="Target BackBox VM IP")
    p.add_argument("--ports", default="22,3389,8080", help="Comma-separated auth ports (default: 22,3389,8080)")
    p.add_argument("--attempts-per-port", type=int, default=200, help="Brute-force attempts per port (default: 200)")
    p.add_argument("--duration", type=int, default=20, help="Max runtime seconds (default: 20)")
    args = p.parse_args()
    brute_force_signature(args.target, _parse_ports(args.ports), args.attempts_per_port, args.duration)


if __name__ == "__main__":
    main()
