"""
Default signature rules definitions for SAGEDRAL-ML rule-based detection engine.
"""

from typing import List, Dict, Any, Callable

SIGNATURE_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "SIG-001",
        "name": "SYN Flood",
        "description": "High volume of SYN packets without ACK responses in short duration",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow.get("syn_flag_count", 0) > 100 and
            flow.get("ack_flag_count", 0) < 10 and
            flow.get("duration", 100) < 5.0
        ),
        "attack_type": "DDoS",
    },
    {
        "rule_id": "SIG-002",
        "name": "Port Scan (SYN)",
        "description": "SYN packets sent with minimal data exchange",
        "severity": "MEDIUM",
        "condition": lambda flow: (
            flow.get("total_fwd_packets", 0) < 3 and
            flow.get("syn_flag_count", 0) >= 1 and
            flow.get("fin_flag_count", 0) == 0 and
            flow.get("total_bwd_packets", 0) == 0
        ),
        "attack_type": "PortScan",
    },
    {
        "rule_id": "SIG-003",
        "name": "ICMP Flood",
        "description": "Abnormal volume of ICMP traffic per second",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow.get("protocol", 0) == 1 and
            flow.get("flow_packets_per_sec", 0) > 1000
        ),
        "attack_type": "DDoS",
    },
    {
        "rule_id": "SIG-004",
        "name": "Large Outbound Transfer",
        "description": "Very large outbound byte transfer exceeding exfiltration threshold (>100MB)",
        "severity": "MEDIUM",
        "condition": lambda flow: (
            flow.get("total_bwd_bytes", 0) > 100_000_000
        ),
        "attack_type": "Exfiltration",
    },
    {
        "rule_id": "SIG-005",
        "name": "Brute Force SSH",
        "description": "Repeated connection attempts to SSH port 22 in short duration",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow.get("dst_port", 0) == 22 and
            flow.get("total_fwd_packets", 0) > 50 and
            flow.get("duration", 100) < 30.0
        ),
        "attack_type": "BruteForce",
    },
    {
        "rule_id": "SIG-006",
        "name": "Brute Force RDP",
        "description": "Repeated connection attempts to RDP port 3389",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow.get("dst_port", 0) == 3389 and
            flow.get("total_fwd_packets", 0) > 30 and
            flow.get("duration", 100) < 60.0
        ),
        "attack_type": "BruteForce",
    },
    {
        "rule_id": "SIG-007",
        "name": "UDP Flood",
        "description": "Extremely high UDP packet throughput per second",
        "severity": "HIGH",
        "condition": lambda flow: (
            flow.get("protocol", 0) == 17 and
            flow.get("flow_packets_per_sec", 0) > 5000
        ),
        "attack_type": "DDoS",
    },
]
