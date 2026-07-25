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
        "params": {"min_syn_count": 100, "max_ack_count": 10, "max_duration": 5.0},
        "condition": lambda flow, params: (
            flow.get("syn_flag_count", 0) > params["min_syn_count"] and
            flow.get("ack_flag_count", 0) < params["max_ack_count"] and
            flow.get("duration", 100) < params["max_duration"]
        ),
        "attack_type": "DDoS",
    },
    {
        "rule_id": "SIG-002",
        "name": "Port Scan (SYN)",
        "description": "SYN packets sent with minimal data exchange",
        "severity": "MEDIUM",
        "params": {"max_fwd_packets": 3, "min_syn_count": 1},
        "condition": lambda flow, params: (
            flow.get("total_fwd_packets", 0) < params["max_fwd_packets"] and
            flow.get("syn_flag_count", 0) >= params["min_syn_count"] and
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
        "params": {"min_packets_per_sec": 1000},
        "condition": lambda flow, params: (
            flow.get("protocol", 0) == 1 and
            flow.get("flow_packets_per_sec", 0) > params["min_packets_per_sec"]
        ),
        "attack_type": "DDoS",
    },
    {
        "rule_id": "SIG-004",
        "name": "Large Outbound Transfer",
        "description": "Very large outbound byte transfer exceeding exfiltration threshold (>100MB)",
        "severity": "MEDIUM",
        "params": {"min_bwd_bytes": 100_000_000},
        "condition": lambda flow, params: (
            flow.get("total_bwd_bytes", 0) > params["min_bwd_bytes"]
        ),
        "attack_type": "Exfiltration",
    },
    {
        "rule_id": "SIG-005",
        "name": "Brute Force SSH",
        "description": "Repeated connection attempts to SSH port 22 in short duration",
        "severity": "HIGH",
        "params": {"dst_port": 22, "min_fwd_packets": 50, "max_duration": 30.0},
        "condition": lambda flow, params: (
            flow.get("dst_port", 0) == params["dst_port"] and
            flow.get("total_fwd_packets", 0) > params["min_fwd_packets"] and
            flow.get("duration", 100) < params["max_duration"]
        ),
        "attack_type": "BruteForce",
    },
    {
        "rule_id": "SIG-006",
        "name": "Brute Force RDP",
        "description": "Repeated connection attempts to RDP port 3389",
        "severity": "HIGH",
        "params": {"dst_port": 3389, "min_fwd_packets": 30, "max_duration": 60.0},
        "condition": lambda flow, params: (
            flow.get("dst_port", 0) == params["dst_port"] and
            flow.get("total_fwd_packets", 0) > params["min_fwd_packets"] and
            flow.get("duration", 100) < params["max_duration"]
        ),
        "attack_type": "BruteForce",
    },
    {
        "rule_id": "SIG-007",
        "name": "UDP Flood",
        "description": "Extremely high UDP packet throughput per second",
        "severity": "HIGH",
        "params": {"min_packets_per_sec": 5000},
        "condition": lambda flow, params: (
            flow.get("protocol", 0) == 17 and
            flow.get("flow_packets_per_sec", 0) > params["min_packets_per_sec"]
        ),
        "attack_type": "DDoS",
    },
]
