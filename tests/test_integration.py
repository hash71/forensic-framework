"""
Integration tests — run scenarios through the full pipeline.
"""

import json
from pathlib import Path

from app.normalizer.normalizer import normalize_scenario
from app.rules.rule_engine import run_rules

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_baselines():
    with open(PROJECT_ROOT / "data" / "user_baselines.json", "r") as f:
        return json.load(f)


def _load_normalized_events(scenario_num):
    path = PROJECT_ROOT / "data" / "normalized" / f"scenario_{scenario_num}_events.json"
    with open(path, "r") as f:
        return json.load(f)


# ── Scenario 1: normal_baseline (BENIGN) ────────────────────────────────────

def test_scenario_1_end_to_end():
    """Scenario 1 is BENIGN — run rules and verify no critical alerts, verdict = no_alert."""
    events = _load_normalized_events(1)
    baselines = _load_baselines()

    alerts = run_rules(events, baselines)

    # Determine verdict the same way rule_engine.evaluate_scenario does
    severity_summary = {"warning": 0, "critical": 0}
    for a in alerts:
        sev = a["severity"]
        if sev in severity_summary:
            severity_summary[sev] += 1

    if not alerts:
        verdict = "no_alert"
    elif severity_summary["critical"] > 0:
        verdict = "attack"
    else:
        verdict = "suspicious"

    assert verdict == "no_alert", (
        f"Scenario 1 (BENIGN) should produce no_alert but got '{verdict}' "
        f"with {len(alerts)} alert(s)"
    )
    assert len(alerts) == 0


# ── Scenario 3: obvious_attack (ATTACK) ─────────────────────────────────────

def test_scenario_3_end_to_end():
    """Scenario 3 is an obvious ATTACK — rules should detect it with critical alerts."""
    events = _load_normalized_events(3)
    baselines = _load_baselines()

    alerts = run_rules(events, baselines)

    severity_summary = {"warning": 0, "critical": 0}
    for a in alerts:
        sev = a["severity"]
        if sev in severity_summary:
            severity_summary[sev] += 1

    if not alerts:
        verdict = "no_alert"
    elif severity_summary["critical"] > 0:
        verdict = "attack"
    else:
        verdict = "suspicious"

    assert verdict == "attack", (
        f"Scenario 3 (ATTACK) should produce verdict 'attack' but got '{verdict}'"
    )

    rules_triggered = sorted(set(a["rule_id"] for a in alerts))

    # Key attack rules that must fire for the obvious attack
    assert "R001" in rules_triggered, "R001 (unusual_login_ip) should fire"
    assert "R003" in rules_triggered, "R003 (privilege_escalation) should fire"
    assert "R004" in rules_triggered, "R004 (bulk_download) should fire"
    assert "R006" in rules_triggered, "R006 (log_deletion) should fire"
    assert "R007" in rules_triggered, "R007 (failed_login_spike) should fire"
    assert "R008" in rules_triggered, "R008 (privilege_then_download) should fire"

    # Verify critical count
    assert severity_summary["critical"] >= 3, (
        f"Expected at least 3 critical alerts, got {severity_summary['critical']}"
    )
