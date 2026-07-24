"""
SQLAlchemy ORM models for SAGEDRAL-ML database schema.
"""

import time
import json
from sqlalchemy import (
    Column,
    Integer,
    String,
    Float,
    Text,
    Index,
    func,
)
from sagedral_ml.database.connection import Base


class AlertModel(Base):
    """Stores all detected network security alerts."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), unique=True, nullable=False, index=True)
    timestamp = Column(Float, nullable=False, index=True)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    attack_type = Column(String(50), nullable=True, index=True)
    severity = Column(String(20), nullable=True, index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    final_score = Column(Float, nullable=False)
    action_taken = Column(String(30), nullable=False)  # BLOCKED, ALERTED, ALLOWED
    signature_matched = Column(Text, nullable=True)  # JSON string array
    ml_anomaly_score = Column(Float, nullable=True)
    flow_duration = Column(Float, nullable=True)
    total_bytes = Column(Integer, nullable=True)
    created_at = Column(Float, default=time.time)

    def to_dict(self):
        sig_matched = []
        if self.signature_matched:
            try:
                sig_matched = json.loads(self.signature_matched)
            except Exception:
                sig_matched = [self.signature_matched]
        return {
            "id": self.id,
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
            "signature_matched": sig_matched,
            "ml_anomaly_score": self.ml_anomaly_score,
            "flow_duration": self.flow_duration,
            "total_bytes": self.total_bytes,
            "created_at": self.created_at,
        }


class BlockedIPModel(Base):
    """Stores active and historical IP block actions."""
    __tablename__ = "blocked_ips"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    blocked_at = Column(Float, nullable=False)
    reason = Column(Text, nullable=True)
    alert_id = Column(String(64), nullable=True)
    auto_unblock_at = Column(Float, nullable=True)  # NULL = permanent
    blocked_by = Column(String(30), default="system")  # system or manual
    is_active = Column(Integer, default=1, index=True)  # 1=active, 0=unblocked

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "blocked_at": self.blocked_at,
            "reason": self.reason,
            "alert_id": self.alert_id,
            "auto_unblock_at": self.auto_unblock_at,
            "blocked_by": self.blocked_by,
            "is_active": bool(self.is_active),
        }


class TrafficStatModel(Base):
    """Time-series network traffic metrics for dashboard visualization."""
    __tablename__ = "traffic_stats"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, index=True)
    packets_per_sec = Column(Float, default=0.0)
    bytes_per_sec = Column(Float, default=0.0)
    alerts_count = Column(Integer, default=0)
    flows_count = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "packets_per_sec": self.packets_per_sec,
            "bytes_per_sec": self.bytes_per_sec,
            "alerts_count": self.alerts_count,
            "flows_count": self.flows_count,
        }


class ConfigHistoryModel(Base):
    """Audit trail of configuration updates."""
    __tablename__ = "config_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    changed_at = Column(Float, default=time.time)
    changed_by = Column(String(50), default="admin")
    config_key = Column(String(100), nullable=False)
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)


class SignatureRuleModel(Base):
    """Custom rule definitions added via API."""
    __tablename__ = "signature_rules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    rule_id = Column(String(50), unique=True, nullable=False, index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False)
    condition_expr = Column(Text, nullable=False)
    attack_type = Column(String(50), nullable=False)
    is_enabled = Column(Integer, default=1)
    created_at = Column(Float, default=time.time)

    def to_dict(self):
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "condition_expr": self.condition_expr,
            "attack_type": self.attack_type,
            "is_enabled": bool(self.is_enabled),
            "created_at": self.created_at,
        }
