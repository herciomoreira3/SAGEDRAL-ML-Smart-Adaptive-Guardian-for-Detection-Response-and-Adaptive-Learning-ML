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
    status = Column(String(20), default="open", index=True)  # open, closed, investigated
    feedback_label = Column(String(30), nullable=True, index=True)
    feedback_notes = Column(Text, nullable=True)
    closed_at = Column(Float, nullable=True)
    created_at = Column(Float, default=time.time)

    __table_args__ = (
        Index("idx_alerts_severity_ts", "severity", "timestamp"),
        Index("idx_alerts_src_ts", "src_ip", "timestamp"),
        Index("idx_alerts_attack_ts", "attack_type", "timestamp"),
    )

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
            "status": self.status or "open",
            "feedback_label": self.feedback_label,
            "feedback_notes": self.feedback_notes,
            "closed_at": self.closed_at,
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

    __table_args__ = (
        Index("idx_blocked_active_ts", "is_active", "blocked_at"),
        Index("idx_blocked_expiry", "is_active", "auto_unblock_at"),
    )

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


class UserModel(Base):
    """Registered users for RBAC access to SAGEDRAL-ML API and Dashboard."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="viewer", index=True)  # admin, analyst, viewer
    full_name = Column(String(150), nullable=True)
    email = Column(String(255), nullable=True, index=True)
    is_active = Column(Integer, default=1, index=True)  # 1=active, 0=disabled
    created_at = Column(Float, default=time.time)
    last_login = Column(Float, nullable=True)

    __table_args__ = (
        Index("idx_users_role_active", "role", "is_active"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "full_name": self.full_name,
            "email": self.email,
            "is_active": bool(self.is_active),
            "created_at": self.created_at,
            "last_login": self.last_login,
        }


class AuditLogModel(Base):
    """Comprehensive audit trail for all sensitive operations in SAGEDRAL-ML."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Float, nullable=False, default=time.time, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(50), nullable=True, index=True)
    action_type = Column(String(50), nullable=False, index=True)  # login, logout, block_ip, unblock_ip, config_update, rule_create, user_create, ...
    target_entity = Column(String(50), nullable=True, index=True)  # user, blocked_ip, alert, config, rule
    target_id = Column(String(100), nullable=True, index=True)  # target identifier (IP, id string, etc.)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    detail_json = Column(Text, nullable=True)  # JSON string with additional context

    __table_args__ = (
        Index("idx_audit_user_action", "user_id", "action_type", "timestamp"),
        Index("idx_audit_entity_target", "target_entity", "target_id", "timestamp"),
    )

    def to_dict(self):
        detail = None
        if self.detail_json:
            try:
                detail = json.loads(self.detail_json)
            except Exception:
                detail = self.detail_json
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "username": self.username,
            "action_type": self.action_type,
            "target_entity": self.target_entity,
            "target_id": self.target_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "detail": detail,
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


class IPOffenseHistoryModel(Base):
    """Tracks repeated offender strikes for IP block duration escalation."""
    __tablename__ = "ip_offense_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    first_offense_at = Column(Float, nullable=False, default=time.time)
    last_offense_at = Column(Float, nullable=False, default=time.time, index=True)
    strike_count = Column(Integer, nullable=False, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "ip": self.ip,
            "first_offense_at": self.first_offense_at,
            "last_offense_at": self.last_offense_at,
            "strike_count": self.strike_count,
        }


class AlertFeedbackModel(Base):
    """Stores active-learning labels provided by analysts."""
    __tablename__ = "alert_feedback"

    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_id = Column(String(64), nullable=False, index=True)
    label = Column(String(30), nullable=False, index=True)
    notes = Column(Text, nullable=True)
    created_at = Column(Float, nullable=False, default=time.time, index=True)
    created_by = Column(String(50), nullable=True, index=True)

    __table_args__ = (
        Index("idx_feedback_alert_created", "alert_id", "created_at"),
    )

    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "label": self.label,
            "notes": self.notes,
            "created_at": self.created_at,
            "created_by": self.created_by,
        }


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
