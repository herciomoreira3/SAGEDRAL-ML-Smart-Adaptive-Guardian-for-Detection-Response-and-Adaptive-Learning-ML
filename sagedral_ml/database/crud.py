"""
Asynchronous CRUD operations for database layer.
"""

import json
import time
import logging
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy import select, update, delete, func, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from sagedral_ml.database.models import (
    AlertModel,
    BlockedIPModel,
    TrafficStatModel,
    ConfigHistoryModel,
    SignatureRuleModel,
    IPOffenseHistoryModel,
    AlertFeedbackModel,
)

logger = logging.getLogger("sagedral_ml.database.crud")


# ================= ALERTS CRUD =================

async def create_alert(db: AsyncSession, alert_data: Dict[str, Any]) -> AlertModel:
    sig_matched = alert_data.get("signature_matched", [])
    if isinstance(sig_matched, (list, tuple)):
        sig_matched_json = json.dumps(sig_matched)
    else:
        sig_matched_json = str(sig_matched)

    alert = AlertModel(
        alert_id=alert_data["alert_id"],
        timestamp=alert_data.get("timestamp", time.time()),
        src_ip=alert_data["src_ip"],
        dst_ip=alert_data["dst_ip"],
        src_port=alert_data.get("src_port"),
        dst_port=alert_data.get("dst_port"),
        protocol=alert_data.get("protocol"),
        attack_type=alert_data.get("attack_type"),
        severity=alert_data.get("severity"),
        final_score=alert_data["final_score"],
        action_taken=alert_data["action_taken"],
        signature_matched=sig_matched_json,
        ml_anomaly_score=alert_data.get("ml_anomaly_score"),
        flow_duration=alert_data.get("flow_duration"),
        total_bytes=alert_data.get("total_bytes"),
        status=alert_data.get("status", "open"),
    )
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


async def get_alerts(
    db: AsyncSession,
    page: int = 1,
    limit: int = 50,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    src_ip: Optional[str] = None,
    start_time: Optional[float] = None,
    end_time: Optional[float] = None,
) -> Tuple[List[AlertModel], int]:
    filters = []
    if severity:
        filters.append(AlertModel.severity == severity.upper())
    if attack_type:
        filters.append(AlertModel.attack_type.ilike(f"%{attack_type}%"))
    if src_ip:
        filters.append(AlertModel.src_ip == src_ip)
    if start_time is not None:
        filters.append(AlertModel.timestamp >= start_time)
    if end_time is not None:
        filters.append(AlertModel.timestamp <= end_time)

    base_filter = [True] + filters if filters else [True]
    count_query = select(func.count(AlertModel.id)).where(and_(*base_filter))
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    offset = (page - 1) * limit
    query = (
        select(AlertModel)
        .where(and_(*base_filter))
        .order_by(AlertModel.timestamp.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await db.execute(query)
    alerts = res.scalars().all()
    return list(alerts), total


async def get_recent_alerts(db: AsyncSession, limit: int = 10) -> List[AlertModel]:
    query = select(AlertModel).order_by(AlertModel.timestamp.desc()).limit(limit)
    res = await db.execute(query)
    return list(res.scalars().all())


async def get_alert_by_alert_id(db: AsyncSession, alert_id: str) -> Optional[AlertModel]:
    stmt = select(AlertModel).where(AlertModel.alert_id == alert_id)
    res = await db.execute(stmt)
    return res.scalar_one_or_none()


async def close_alert(db: AsyncSession, alert_id: str) -> bool:
    stmt = (
        update(AlertModel)
        .where(AlertModel.alert_id == alert_id)
        .values(status="closed", closed_at=time.time())
    )
    res = await db.execute(stmt)
    await db.commit()
    return res.rowcount > 0


async def delete_alert(db: AsyncSession, alert_id: str) -> bool:
    stmt = delete(AlertModel).where(AlertModel.alert_id == alert_id)
    res = await db.execute(stmt)
    await db.commit()
    return res.rowcount > 0


async def bulk_delete_alerts(db: AsyncSession, alert_ids: List[str]) -> int:
    if not alert_ids:
        return 0
    stmt = delete(AlertModel).where(AlertModel.alert_id.in_(alert_ids))
    res = await db.execute(stmt)
    await db.commit()
    return int(res.rowcount or 0)


async def create_alert_feedback(
    db: AsyncSession,
    feedback_data: Dict[str, Any],
) -> AlertFeedbackModel:
    alert = await get_alert_by_alert_id(db, feedback_data["alert_id"])
    if alert is None:
        raise ValueError(f"Alert {feedback_data['alert_id']} not found")

    label = str(feedback_data["label"]).upper()
    notes = feedback_data.get("notes") or ""
    created_by = feedback_data.get("created_by")

    feedback = AlertFeedbackModel(
        alert_id=feedback_data["alert_id"],
        label=label,
        notes=notes,
        created_by=created_by,
    )
    db.add(feedback)
    alert.feedback_label = label
    alert.feedback_notes = notes
    await db.commit()
    await db.refresh(feedback)
    return feedback


# ================= BLOCKED IPS CRUD =================

async def block_ip_db(
    db: AsyncSession,
    ip: str,
    reason: str = "Threat detected",
    alert_id: Optional[str] = None,
    duration_seconds: Optional[int] = 3600,
    blocked_by: str = "system",
) -> BlockedIPModel:
    now = time.time()
    auto_unblock_at = (now + duration_seconds) if duration_seconds and duration_seconds > 0 else None

    # Check if already exists
    stmt = select(BlockedIPModel).where(BlockedIPModel.ip == ip)
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()

    if existing:
        existing.blocked_at = now
        existing.reason = reason
        existing.alert_id = alert_id
        existing.auto_unblock_at = auto_unblock_at
        existing.blocked_by = blocked_by
        existing.is_active = 1
        await db.commit()
        await db.refresh(existing)
        return existing
    else:
        blocked_ip = BlockedIPModel(
            ip=ip,
            blocked_at=now,
            reason=reason,
            alert_id=alert_id,
            auto_unblock_at=auto_unblock_at,
            blocked_by=blocked_by,
            is_active=1,
        )
        db.add(blocked_ip)
        await db.commit()
        await db.refresh(blocked_ip)
        return blocked_ip


async def record_ip_offense(db: AsyncSession, ip: str) -> IPOffenseHistoryModel:
    now = time.time()
    stmt = select(IPOffenseHistoryModel).where(IPOffenseHistoryModel.ip == ip)
    res = await db.execute(stmt)
    existing = res.scalar_one_or_none()

    if existing:
        existing.last_offense_at = now
        existing.strike_count = int(existing.strike_count or 0) + 1
        await db.commit()
        await db.refresh(existing)
        return existing

    offense = IPOffenseHistoryModel(
        ip=ip,
        first_offense_at=now,
        last_offense_at=now,
        strike_count=1,
    )
    db.add(offense)
    await db.commit()
    await db.refresh(offense)
    return offense


async def unblock_ip_db(db: AsyncSession, ip: str) -> bool:
    stmt = update(BlockedIPModel).where(BlockedIPModel.ip == ip).values(is_active=0)
    res = await db.execute(stmt)
    await db.commit()
    return res.rowcount > 0


async def get_active_blocked_ips(db: AsyncSession) -> List[BlockedIPModel]:
    stmt = select(BlockedIPModel).where(BlockedIPModel.is_active == 1).order_by(BlockedIPModel.blocked_at.desc())
    res = await db.execute(stmt)
    return list(res.scalars().all())


async def is_ip_blocked_db(db: AsyncSession, ip: str) -> bool:
    stmt = select(func.count(BlockedIPModel.id)).where(
        and_(BlockedIPModel.ip == ip, BlockedIPModel.is_active == 1)
    )
    res = await db.execute(stmt)
    return (res.scalar() or 0) > 0


async def get_expired_blocked_ips(db: AsyncSession, now: Optional[float] = None) -> List[BlockedIPModel]:
    if now is None:
        now = time.time()
    stmt = select(BlockedIPModel).where(
        and_(
            BlockedIPModel.is_active == 1,
            BlockedIPModel.auto_unblock_at.isnot(None),
            BlockedIPModel.auto_unblock_at <= now,
        )
    )
    res = await db.execute(stmt)
    return list(res.scalars().all())


# ================= TRAFFIC STATS CRUD =================

async def add_traffic_stat(
    db: AsyncSession,
    packets_per_sec: float,
    bytes_per_sec: float,
    alerts_count: int = 0,
    flows_count: int = 0,
    timestamp: Optional[float] = None,
) -> TrafficStatModel:
    stat = TrafficStatModel(
        timestamp=timestamp or time.time(),
        packets_per_sec=packets_per_sec,
        bytes_per_sec=bytes_per_sec,
        alerts_count=alerts_count,
        flows_count=flows_count,
    )
    db.add(stat)
    await db.commit()
    await db.refresh(stat)
    return stat


async def get_traffic_stats(db: AsyncSession, limit: int = 60) -> List[TrafficStatModel]:
    stmt = select(TrafficStatModel).order_by(TrafficStatModel.timestamp.desc()).limit(limit)
    res = await db.execute(stmt)
    stats = list(res.scalars().all())
    stats.reverse()
    return stats


# ================= CUSTOM RULES CRUD =================

async def create_signature_rule(db: AsyncSession, rule_data: Dict[str, Any]) -> SignatureRuleModel:
    rule = SignatureRuleModel(
        rule_id=rule_data["rule_id"],
        name=rule_data["name"],
        description=rule_data.get("description", ""),
        severity=rule_data["severity"].upper(),
        condition_expr=rule_data["condition_expr"],
        attack_type=rule_data["attack_type"],
        is_enabled=1 if rule_data.get("is_enabled", True) else 0,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return rule


async def get_custom_signature_rules(db: AsyncSession) -> List[SignatureRuleModel]:
    stmt = select(SignatureRuleModel).where(SignatureRuleModel.is_enabled == 1)
    res = await db.execute(stmt)
    return list(res.scalars().all())


# ================= CONFIG HISTORY / AUDIT =================

async def create_config_history_entries(
    db: AsyncSession,
    changes: Dict[str, Tuple[Any, Any]],
    changed_by: str = "system",
) -> int:
    count = 0
    for key, (old_value, new_value) in changes.items():
        entry = ConfigHistoryModel(
            changed_at=time.time(),
            changed_by=changed_by,
            config_key=key,
            old_value=json.dumps(old_value, default=str),
            new_value=json.dumps(new_value, default=str),
        )
        db.add(entry)
        count += 1
    if count:
        await db.commit()
    return count


# ================= RETENTION CLEANUP =================

async def cleanup_old_records(
    db: AsyncSession, retention_alerts_days: int = 30, retention_traffic_days: int = 7
):
    now = time.time()
    alerts_cutoff = now - (retention_alerts_days * 86400)
    traffic_cutoff = now - (retention_traffic_days * 86400)

    stmt_alerts = delete(AlertModel).where(AlertModel.timestamp < alerts_cutoff)
    stmt_traffic = delete(TrafficStatModel).where(TrafficStatModel.timestamp < traffic_cutoff)

    await db.execute(stmt_alerts)
    await db.execute(stmt_traffic)
    await db.commit()
    logger.info("Executed database retention cleanup.")
