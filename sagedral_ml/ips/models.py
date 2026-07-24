"""
AlertEvent dataclass representing a detected security threat event.
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class AlertEvent:
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "TCP"
    attack_type: str = "Unknown"
    severity: str = "LOW"  # LOW, MEDIUM, HIGH, CRITICAL
    final_score: float = 0.0
    action_taken: str = "ALERTED"  # BLOCKED, ALERTED, ALLOWED, WHITELISTED
    signature_matched: List[str] = field(default_factory=list)
    ml_anomaly_score: float = 0.0
    flow_duration: float = 0.0
    total_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "final_score": self.final_score,
            "action_taken": self.action_taken,
            "signature_matched": self.signature_matched,
            "ml_anomaly_score": self.ml_anomaly_score,
            "flow_duration": self.flow_duration,
            "total_bytes": self.total_bytes,
        }
