"""
DecisionEngine class for combining Signature and ML scores into a unified threat action.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from sagedral_ml.detection.signature_engine import SignatureResult
from sagedral_ml.detection.ml_engine import MLResult

logger = logging.getLogger("sagedral_ml.detection.decision")


@dataclass
class DecisionResult:
    is_threat: bool
    final_score: float
    action: str  # "ALLOW", "ALERT", "BLOCK", "ALREADY_BLOCKED"
    attack_type: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float


class DecisionEngine:
    """
    Evaluates Signature and ML results to determine final security action.
    """

    def __init__(
        self,
        alert_threshold: float = 0.5,
        block_threshold: float = 0.7,
        weight_signature: float = 0.4,
        weight_ml: float = 0.6,
        dedup_window: float = 300.0,
    ):
        self.alert_threshold = alert_threshold
        self.block_threshold = block_threshold
        self.weight_signature = weight_signature
        self.weight_ml = weight_ml
        self.dedup_window = dedup_window

        # Deduplication cache: {src_ip: last_alert_timestamp}
        self._dedup_cache: Dict[str, float] = {}
        # Active blocked IP cache: {ip: True}
        self._blocked_ips_cache: Set[str] = set()

    def update_blocked_cache(self, blocked_ips: List[str]) -> None:
        """Update active blocked IP set cache."""
        self._blocked_ips_cache = set(blocked_ips)

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips_cache

    def _score_to_severity(self, score: float) -> str:
        if score >= 0.75:
            return "CRITICAL"
        elif score >= 0.50:
            return "HIGH"
        elif score >= 0.25:
            return "MEDIUM"
        else:
            return "LOW"

    def decide(
        self,
        sig_result: SignatureResult,
        ml_result: MLResult,
        src_ip: str,
        now: Optional[float] = None,
    ) -> DecisionResult:
        current_time = now if now is not None else time.time()

        # Deduplication check
        last_alert_time = self._dedup_cache.get(src_ip, 0.0)
        is_deduped = (current_time - last_alert_time) < self.dedup_window

        # Calculate combined weighted score
        final_score = (self.weight_signature * sig_result.signature_score) + (
            self.weight_ml * ml_result.anomaly_score
        )
        final_score = min(max(final_score, 0.0), 1.0)

        # Determine attack type
        if ml_result.attack_class and ml_result.attack_class != "NORMAL":
            attack_type = ml_result.attack_class
        elif sig_result.attack_types:
            attack_type = sig_result.attack_types[0]
        else:
            attack_type = "Anomaly_Traffic"

        confidence = max(ml_result.class_confidence, sig_result.signature_score)

        # Already blocked check
        if self.is_blocked(src_ip):
            return DecisionResult(
                is_threat=False,
                final_score=final_score,
                action="ALREADY_BLOCKED",
                attack_type=attack_type,
                severity=self._score_to_severity(final_score),
                confidence=confidence,
            )

        # Decision rules
        is_threat = False
        action = "ALLOW"

        if sig_result.max_severity in ("HIGH", "CRITICAL"):
            is_threat = True
            action = "BLOCK"
        elif final_score >= self.block_threshold:
            is_threat = True
            action = "BLOCK"
        elif final_score >= self.alert_threshold:
            is_threat = True
            action = "ALERT"

        if is_threat:
            if is_deduped and action == "ALERT":
                action = "ALLOW"
                is_threat = False
            else:
                self._dedup_cache[src_ip] = current_time

        severity = self._score_to_severity(final_score)
        if sig_result.max_severity in ("HIGH", "CRITICAL"):
            severity = sig_result.max_severity

        return DecisionResult(
            is_threat=is_threat,
            final_score=final_score,
            action=action,
            attack_type=attack_type,
            severity=severity,
            confidence=confidence,
        )
