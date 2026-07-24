"""
Demo seed script - populates database with realistic mock data
so the dashboard looks alive when first opened.

Usage: py -m scripts.seed_demo
"""

import asyncio
import time
import uuid
import random

import sagedral_ml.database.connection as _db_conn
from sagedral_ml.database.connection import init_db
from sagedral_ml.database import crud

ATTACK_SCENARIOS = [
    {"attack_type": "DDoS",         "severity": "CRITICAL", "score": 0.95, "sig": ["SIG-001", "SIG-003"], "action": "BLOCKED"},
    {"attack_type": "PortScan",     "severity": "MEDIUM",   "score": 0.58, "sig": ["SIG-002"],            "action": "ALERTED"},
    {"attack_type": "BruteForce",   "severity": "HIGH",     "score": 0.82, "sig": ["SIG-005"],            "action": "BLOCKED"},
    {"attack_type": "DDoS",         "severity": "HIGH",     "score": 0.78, "sig": ["SIG-007"],            "action": "BLOCKED"},
    {"attack_type": "Exfiltration", "severity": "MEDIUM",   "score": 0.61, "sig": ["SIG-004"],            "action": "ALERTED"},
    {"attack_type": "BruteForce",   "severity": "HIGH",     "score": 0.74, "sig": ["SIG-006"],            "action": "BLOCKED"},
    {"attack_type": "DDoS",         "severity": "CRITICAL", "score": 0.97, "sig": ["SIG-001"],            "action": "BLOCKED"},
    {"attack_type": "PortScan",     "severity": "LOW",      "score": 0.42, "sig": [],                     "action": "ALERTED"},
]

ATTACKER_IPS = [
    "45.33.32.156", "198.51.100.42", "203.0.113.7",  "192.0.2.88",
    "172.16.254.1", "185.220.101.55","91.108.4.200", "104.21.67.88",
]

VICTIM_IPS = ["10.0.0.1", "10.0.0.2", "192.168.1.1", "172.20.0.5"]


async def seed():
    _db_conn.init_engine()
    await init_db()

    now = time.time()
    session_factory = _db_conn.AsyncSessionLocal

    async with session_factory() as db:
        # --- Alerts (30 events over last 24h) ---
        print("Seeding mock alerts...")
        for i in range(30):
            scenario = random.choice(ATTACK_SCENARIOS)
            src_ip = random.choice(ATTACKER_IPS)
            dst_ip = random.choice(VICTIM_IPS)
            ts = now - random.uniform(0, 86400)

            await crud.create_alert(db, {
                "alert_id": str(uuid.uuid4()),
                "timestamp": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443, 22, 3389, 8080, 53]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "attack_type": scenario["attack_type"],
                "severity": scenario["severity"],
                "final_score": round(scenario["score"] + random.uniform(-0.04, 0.04), 4),
                "action_taken": scenario["action"],
                "signature_matched": scenario["sig"],
                "ml_anomaly_score": round(scenario["score"] - 0.05, 4),
                "flow_duration": round(random.uniform(0.1, 60.0), 3),
                "total_bytes": random.randint(1000, 5_000_000),
            })

        # --- Blocked IPs (5 active) ---
        print("Seeding blocked IPs...")
        for ip in ["45.33.32.156", "198.51.100.42", "203.0.113.7", "185.220.101.55", "91.108.4.200"]:
            await crud.block_ip_db(
                db,
                ip=ip,
                reason="Auto-blocked: Threat detected by SAGEDRAL-ML",
                duration_seconds=3600,
                blocked_by="system",
            )

        # --- Traffic Stats (60 samples over last 10 min) ---
        print("Seeding traffic stats...")
        for i in range(60):
            ts = now - (60 - i) * 10
            # Insert spike at sample 30-32 to simulate attack burst
            is_spike = i in range(28, 35)
            pps = random.uniform(100, 800) + (random.uniform(6000, 10000) if is_spike else 0)
            bps = pps * random.uniform(200, 1200)
            await crud.add_traffic_stat(
                db,
                packets_per_sec=pps,
                bytes_per_sec=bps,
                alerts_count=random.randint(0, 5) if is_spike else random.randint(0, 1),
                flows_count=random.randint(5, 50),
                timestamp=ts,
            )

    print("\n[OK] Demo seed loaded! Database populated with:")
    print("     * 30 threat alerts (DDoS, PortScan, BruteForce, Exfiltration)")
    print("     *  5 blocked IPs")
    print("     * 60 traffic stat records (with attack burst spike)")
    print("\n[>>] Dashboard ready at: http://localhost:8000\n")


if __name__ == "__main__":
    asyncio.run(seed())
