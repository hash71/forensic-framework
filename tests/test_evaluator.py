"""
Tests for app.evaluation.evaluator — 5+ tests.
"""

from app.evaluation.evaluator import (
    evaluate_verdict_accuracy,
    evaluate_event_recall,
    evaluate_false_positive_rate,
)


# ── evaluate_verdict_accuracy ────────────────────────────────────────────────

def test_verdict_accuracy_correct_benign():
    """Both engines correctly identify a BENIGN scenario."""
    result = evaluate_verdict_accuracy(
        ground_truth_label="BENIGN",
        rule_verdict="no_alert",
        llm_verdict="NO",
    )
    assert result["ground_truth"] == "BENIGN"
    assert result["rule_mapped"] == "BENIGN"
    assert result["llm_mapped"] == "BENIGN"
    assert result["rule_correct"] is True
    assert result["llm_correct"] is True


def test_verdict_accuracy_correct_attack():
    """Both engines correctly identify an ATTACK scenario."""
    result = evaluate_verdict_accuracy(
        ground_truth_label="ATTACK",
        rule_verdict="attack",
        llm_verdict="YES",
    )
    assert result["rule_mapped"] == "ATTACK"
    assert result["llm_mapped"] == "ATTACK"
    assert result["rule_correct"] is True
    assert result["llm_correct"] is True


def test_verdict_accuracy_incorrect():
    """Rule says no_alert for an ATTACK -> rule_correct is False."""
    result = evaluate_verdict_accuracy(
        ground_truth_label="ATTACK",
        rule_verdict="no_alert",
        llm_verdict="YES",
    )
    assert result["rule_correct"] is False
    assert result["llm_correct"] is True


def test_verdict_accuracy_suspicious_maps_benign():
    """'suspicious' rule verdict should map to BENIGN."""
    result = evaluate_verdict_accuracy(
        ground_truth_label="BENIGN",
        rule_verdict="suspicious",
        llm_verdict="NO",
    )
    assert result["rule_mapped"] == "BENIGN"
    assert result["rule_correct"] is True


# ── evaluate_event_recall ────────────────────────────────────────────────────

def test_event_recall_full():
    """All 6 ground truth steps detected -> 100% recall."""
    ground_truth_steps = [
        "failed_login_attempts",
        "login_unusual_ip",
        "privilege_escalation",
        "bulk_file_download",
        "log_deletion",
        "logout",
    ]
    llm_chain = [
        {"description": "Multiple failed login attempts from Tor exit node"},
        {"description": "Successful login from unusual IP"},
        {"description": "Privilege escalation to admin role"},
        {"description": "Bulk download of sensitive files"},
        {"description": "Log deletion to cover tracks — deleted access log"},
        {"description": "Session logout after exfiltration"},
    ]
    result = evaluate_event_recall(ground_truth_steps, llm_chain)

    assert result["total_steps"] == 6
    assert result["detected_steps"] == 6
    assert result["recall_pct"] == 100.0
    assert result["missed_steps"] == []


def test_event_recall_partial():
    """Only 3 of 6 steps detected -> 50% recall."""
    ground_truth_steps = [
        "failed_login_attempts",
        "login_unusual_ip",
        "privilege_escalation",
        "bulk_file_download",
        "log_deletion",
        "logout",
    ]
    # Only describe 3 of the 6 steps — avoid keywords that match other steps
    llm_chain = [
        {"description": "Privilege escalation to admin"},
        {"description": "Bulk download of HR files"},
        {"description": "Deleted access log to cover tracks"},
    ]
    result = evaluate_event_recall(ground_truth_steps, llm_chain)

    assert result["total_steps"] == 6
    assert result["detected_steps"] == 3
    assert result["recall_pct"] == 50.0
    assert len(result["missed_steps"]) == 3


def test_event_recall_empty_ground_truth():
    """No ground truth steps -> 100% recall by convention."""
    result = evaluate_event_recall([], [])
    assert result["recall_pct"] == 100.0
    assert result["total_steps"] == 0


# ── evaluate_false_positive_rate ─────────────────────────────────────────────

def test_false_positive_rate_benign_no_alerts():
    """BENIGN scenario with no rule alerts and LLM says NO -> 0 FP."""
    result = evaluate_false_positive_rate(
        ground_truth_label="BENIGN",
        rule_alerts=[],
        llm_verdict="NO",
    )
    assert result["rule_fp_count"] == 0
    assert result["llm_fp"] is False


def test_false_positive_rate_benign_with_alerts():
    """BENIGN scenario where rules fire alerts -> those are false positives."""
    fake_alerts = [{"rule_id": "R002"}, {"rule_id": "R005"}]
    result = evaluate_false_positive_rate(
        ground_truth_label="BENIGN",
        rule_alerts=fake_alerts,
        llm_verdict="YES",
    )
    assert result["rule_fp_count"] == 2
    assert result["llm_fp"] is True


def test_false_positive_rate_attack_scenario():
    """ATTACK scenario -> FP metrics are zeroed out (not applicable)."""
    result = evaluate_false_positive_rate(
        ground_truth_label="ATTACK",
        rule_alerts=[{"rule_id": "R003"}],
        llm_verdict="YES",
    )
    assert result["rule_fp_count"] == 0
    assert result["llm_fp"] is False
