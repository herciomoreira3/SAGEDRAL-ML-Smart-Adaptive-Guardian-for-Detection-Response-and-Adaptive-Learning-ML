"""
Unit tests for DecisionEngine.
"""

from sagedral_ml.detection.decision_engine import DecisionEngine
from sagedral_ml.detection.signature_engine import SignatureResult
from sagedral_ml.detection.ml_engine import MLResult


def test_normal_decision_allow():
    engine = DecisionEngine(alert_threshold=0.5, block_threshold=0.7)
    sig = SignatureResult(matched=False, signature_score=0.0)
    ml = MLResult(anomaly_score=0.1, is_anomaly=False, attack_class="NORMAL")

    decision = engine.decide(sig, ml, src_ip="192.168.1.100")
    assert decision.is_threat is False
    assert decision.action == "ALLOW"


def test_high_signature_override_block():
    engine = DecisionEngine(alert_threshold=0.5, block_threshold=0.7)
    sig = SignatureResult(matched=True, matched_rules=["SIG-001"], max_severity="HIGH", signature_score=0.75)
    ml = MLResult(anomaly_score=0.2, is_anomaly=False)

    decision = engine.decide(sig, ml, src_ip="192.168.1.100")
    assert decision.is_threat is True
    assert decision.action == "BLOCK"


def test_combined_score_triggers_block():
    engine = DecisionEngine(alert_threshold=0.5, block_threshold=0.7, weight_signature=0.4, weight_ml=0.6)
    sig = SignatureResult(matched=True, max_severity="MEDIUM", signature_score=0.5)
    ml = MLResult(anomaly_score=0.9, is_anomaly=True, attack_class="DDoS")

    # (0.4 * 0.5) + (0.6 * 0.9) = 0.2 + 0.54 = 0.74 >= 0.7
    decision = engine.decide(sig, ml, src_ip="192.168.1.100")
    assert decision.is_threat is True
    assert decision.action == "BLOCK"


def test_already_blocked_ip():
    engine = DecisionEngine()
    engine.update_blocked_cache(["10.0.0.55"])

    sig = SignatureResult(matched=True, max_severity="HIGH", signature_score=0.75)
    ml = MLResult(anomaly_score=0.9, is_anomaly=True)

    decision = engine.decide(sig, ml, src_ip="10.0.0.55")
    assert decision.action == "ALREADY_BLOCKED"
    assert decision.is_threat is False
