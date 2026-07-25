"""
SignatureEngine class for evaluating rule-based network intrusion signatures.
"""

import logging
import ast
import json
import os
import stat
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

import tomli

from sagedral_ml.config import get_config
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

    def _compile_safe_condition(self, condition_expr: str):
        """Compile a constrained boolean expression into ``lambda flow``.

        Supported examples:
          - syn_flag_count > 100 and ack_flag_count < 10
          - flow.get("dst_port", 0) == 22 and total_fwd_packets > 50

        Disallowed: imports, attribute access except ``flow.get(...)``, function calls
        except ``flow.get``, comprehensions, lambdas/classes, assignments, and builtins.
        """
        if not condition_expr or not isinstance(condition_expr, str):
            raise ValueError("condition_expr must be a non-empty string")
        if len(condition_expr) > 1000:
            raise ValueError("condition_expr too long (max 1000 characters)")

        tree = ast.parse(condition_expr, mode="eval")
        allowed_nodes = (
            ast.Expression,
            ast.BoolOp,
            ast.BinOp,
            ast.UnaryOp,
            ast.Compare,
            ast.Name,
            ast.Load,
            ast.Constant,
            ast.Subscript,
            ast.Index,
            ast.And,
            ast.Or,
            ast.Not,
            ast.Eq,
            ast.NotEq,
            ast.Lt,
            ast.LtE,
            ast.Gt,
            ast.GtE,
            ast.Add,
            ast.Sub,
            ast.Mult,
            ast.Div,
            ast.Mod,
            ast.USub,
            ast.UAdd,
            ast.Call,
            ast.Attribute,
        )

        for node in ast.walk(tree):
            if not isinstance(node, allowed_nodes):
                raise ValueError(f"Unsupported syntax in condition_expr: {node.__class__.__name__}")
            if isinstance(node, ast.Call):
                if not (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "flow"
                    and node.func.attr == "get"
                ):
                    raise ValueError("Only flow.get(...) calls are allowed in condition_expr")
            if isinstance(node, ast.Attribute):
                if not (
                    isinstance(node.ctx, ast.Load)
                    and node.attr == "get"
                    and isinstance(getattr(node, "value", None), ast.Name)
                    and node.value.id == "flow"
                ):
                    raise ValueError("Only flow.get attribute access is allowed")
            if isinstance(node, ast.Name) and node.id.startswith("__"):
                raise ValueError("Dunder names are not allowed")

        code = compile(tree, "<signature_condition>", "eval")

        def _condition(flow: Dict[str, Any]) -> bool:
            safe_locals = {"flow": flow}
            for key, value in flow.items():
                if isinstance(key, str) and key.isidentifier() and not key.startswith("__"):
                    safe_locals[key] = value
            return bool(eval(code, {"__builtins__": {}}, safe_locals))

        return _condition

    def _load_custom_rules(self, custom_rules_file: str) -> None:
        try:
            cfg = get_config()
            custom_rules_dir = os.path.abspath(
                cfg.get("signature", "custom_rules_dir", "/var/lib/sagedral-ml/custom-rules")
            )
            candidate = os.path.abspath(custom_rules_file)
            if os.path.commonpath([candidate, custom_rules_dir]) != custom_rules_dir:
                logger.error(
                    f"Refusing custom_rules_file outside whitelisted directory: {candidate} "
                    f"(allowed: {custom_rules_dir})"
                )
                return
            if not os.path.exists(candidate):
                logger.warning(f"custom_rules_file not found: {candidate}")
                return
            try:
                mode = os.stat(candidate).st_mode
                if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    logger.error(f"Refusing executable custom_rules_file: {candidate}")
                    return
            except Exception:
                pass

            if candidate.endswith(".json"):
                with open(candidate, "r", encoding="utf-8") as f:
                    custom_rules = json.load(f)
            elif candidate.endswith(".toml"):
                with open(candidate, "rb") as f:
                    loaded = tomli.load(f)
                custom_rules = loaded.get("rules", [])
            else:
                logger.error(
                    f"Refusing unsafe custom rules file extension for {candidate}. "
                    "Use JSON/TOML with condition_expr, not executable Python."
                )
                return

            added = 0
            for raw_rule in custom_rules:
                condition_expr = raw_rule.get("condition_expr") or raw_rule.get("condition")
                compiled = self._compile_safe_condition(condition_expr)
                self.rules.append({
                    "rule_id": raw_rule["rule_id"],
                    "name": raw_rule.get("name", raw_rule["rule_id"]),
                    "description": raw_rule.get("description", ""),
                    "severity": raw_rule.get("severity", "LOW"),
                    "attack_type": raw_rule.get("attack_type", "Custom"),
                    "condition": compiled,
                    "from_file": True,
                })
                added += 1
            logger.info(f"Loaded {added} sandboxed custom signature rules from {candidate}")
        except Exception as e:
            logger.error(f"Failed to load custom signature rules from {custom_rules_file}: {e}")

    async def load_rules_from_db(self, db_session) -> int:
        """Load enabled custom signature rules from database."""
        try:
            from sagedral_ml.database import crud
            db_rules = await crud.get_custom_signature_rules(db_session)
        except Exception as e:
            logger.error(f"Failed to query custom signature rules from DB: {e}")
            return 0

        existing_rule_ids = {r.get("rule_id") for r in self.rules}
        added = 0
        for db_rule in db_rules:
            if db_rule.rule_id in existing_rule_ids:
                continue
            try:
                compiled = self._compile_safe_condition(db_rule.condition_expr)
                self.rules.append({
                    "rule_id": db_rule.rule_id,
                    "name": db_rule.name,
                    "description": db_rule.description,
                    "severity": db_rule.severity,
                    "attack_type": db_rule.attack_type,
                    "condition": compiled,
                    "from_db": True,
                })
                existing_rule_ids.add(db_rule.rule_id)
                added += 1
            except Exception as e:
                logger.error(f"Skip DB signature rule {db_rule.rule_id}: invalid condition_expr: {e}")
        logger.info(f"Loaded {added} custom signature rules from database.")
        return added

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
                params = rule.get("params", {})
                try:
                    matched = condition(feature_vector, params)
                except TypeError:
                    matched = condition(feature_vector)
                if matched:
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
