"""
SignatureEngine class for evaluating rule-based network intrusion signatures.
"""

import logging
import importlib.util
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

from sagedral_ml.detection.rules.default_rules import SIGNATURE_RULES

logger = logging.getLogger("sagedral_ml.detection.signature")

SEVERITY_SCORE_MAP = {
    "NONE": 0.0,
    "LOW": 0.25,
    "MEDIUM": 0.50,
    "HIGH": 0.75,
    "CRITICAL": 1.00,
}

SEVERITY_RANK = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


@dataclass
class SignatureResult:
    matched: bool = False
    matched_rules: List[str] = field(default_factory=list)
    max_severity: str = "NONE"
    attack_types: List[str] = field(default_factory=list)
    signature_score: float = 0.0


class SignatureEngine:
    """
    Evaluates network flow feature vectors against explicit signature rules.
    """

    def __init__(
        self,
        disabled_rules: Optional[List[str]] = None,
        custom_rules_file: Optional[str] = None,
    ):
        self.disabled_rules = set(disabled_rules or [])
        self.rules: List[Dict[str, Any]] = list(SIGNATURE_RULES)

        if custom_rules_file:
            self._load_custom_rules(custom_rules_file)

    def _load_custom_rules(self, custom_rules_file: str) -> None:
        try:
            spec = importlib.util.spec_from_file_location("custom_rules_module", custom_rules_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                custom_rules = getattr(module, "SIGNATURE_RULES", [])
                self.rules.extend(custom_rules)
                logger.info(f"Loaded {len(custom_rules)} custom signature rules from {custom_rules_file}")
        except Exception as e:
            logger.error(f"Failed to load custom signature rules from {custom_rules_file}: {e}")

    def evaluate(self, feature_vector: Dict[str, Any]) -> SignatureResult:
        matched_rules = []
        attack_types = []
        highest_severity = "NONE"

        for rule in self.rules:
            rule_id = rule.get("rule_id", "")
            if rule_id in self.disabled_rules:
                continue

            condition = rule.get("condition")
            if not callable(condition):
                continue

            try:
                if condition(feature_vector):
                    matched_rules.append(rule_id)
                    attack_type = rule.get("attack_type", "Unknown")
                    if attack_type not in attack_types:
                        attack_types.append(attack_type)

                    severity = rule.get("severity", "LOW").upper()
                    if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(highest_severity, 0):
                        highest_severity = severity
            except Exception as e:
                logger.debug(f"Error evaluating rule {rule_id}: {e}")

        matched = len(matched_rules) > 0
        signature_score = SEVERITY_SCORE_MAP.get(highest_severity, 0.0)

        return SignatureResult(
            matched=matched,
            matched_rules=matched_rules,
            max_severity=highest_severity,
            attack_types=attack_types,
            signature_score=signature_score,
        )
