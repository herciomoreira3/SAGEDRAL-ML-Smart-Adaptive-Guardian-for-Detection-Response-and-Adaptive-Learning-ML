"""
Unit tests for SignatureEngine.
"""

from sagedral_ml.detection.signature_engine import SignatureEngine
from tests.fixtures.mock_flows import (
    MOCK_NORMAL_FLOW,
    MOCK_SYN_FLOOD_FLOW,
    MOCK_SSH_BRUTEFORCE_FLOW,
    MOCK_ICMP_FLOOD_FLOW,
    MOCK_EXFILTRATION_FLOW,
)


def test_normal_traffic_not_flagged():
    engine = SignatureEngine()
    result = engine.evaluate(MOCK_NORMAL_FLOW)
    assert result.matched is False
    assert len(result.matched_rules) == 0
    assert result.signature_score == 0.0


def test_syn_flood_detected():
    engine = SignatureEngine()
    result = engine.evaluate(MOCK_SYN_FLOOD_FLOW)
    assert result.matched is True
    assert "SIG-001" in result.matched_rules
    assert result.max_severity == "HIGH"
    assert result.signature_score == 0.75


def test_ssh_bruteforce_detected():
    engine = SignatureEngine()
    result = engine.evaluate(MOCK_SSH_BRUTEFORCE_FLOW)
    assert result.matched is True
    assert "SIG-005" in result.matched_rules


def test_icmp_flood_detected():
    engine = SignatureEngine()
    result = engine.evaluate(MOCK_ICMP_FLOOD_FLOW)
    assert result.matched is True
    assert "SIG-003" in result.matched_rules


def test_exfiltration_detected():
    engine = SignatureEngine()
    result = engine.evaluate(MOCK_EXFILTRATION_FLOW)
    assert result.matched is True
    assert "SIG-004" in result.matched_rules


def test_disabled_rules_skipped():
    engine = SignatureEngine(disabled_rules=["SIG-001"])
    result = engine.evaluate(MOCK_SYN_FLOOD_FLOW)
    assert "SIG-001" not in result.matched_rules
