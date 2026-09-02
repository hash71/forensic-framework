"""Tests for transparent and classical warrant-study baselines."""

from __future__ import annotations

import json

import pytest

from app.evaluation.warrant_baselines import (
    extract_features,
    run_baselines,
    summarize_predictions,
    tuned_rule_verdict,
    write_baseline_results,
)
from app.ingestion.warrant_benchmark import generate_cases


@pytest.fixture(scope="module")
def cases():
    return generate_cases()


def _case(cases, base_case_id, variant):
    return next(
        case for case in cases
        if case["base_case_id"] == base_case_id and case["variant"] == variant
    )


def test_feature_extractor_is_fixed_and_numeric(cases):
    features = extract_features(_case(cases, "fw2_001", "canonical"))
    assert len(features) >= 35
    assert all(isinstance(value, float) for value in features.values())
    assert features["successful_unauthorized_count"] > 0
    assert features["alert_count"] == 1


def test_events_only_features_remove_alert_signal(cases):
    case = _case(cases, "fw2_001", "canonical")
    with_alerts = extract_features(case, include_alerts=True)
    without_alerts = extract_features(case, include_alerts=False)
    assert with_alerts["alert_count"] == 1
    assert without_alerts["alert_count"] == 0
    assert with_alerts["event_count"] == without_alerts["event_count"]


def test_schema_drift_is_explicitly_measured(cases):
    case = _case(cases, "fw2_001", "schema_drift")
    features = extract_features(case)
    assert features["schema_drift_count"] > 0
    assert features["action__file_download"] == 1


def test_rules_do_not_turn_failed_decoy_logins_into_breach(cases):
    case = _case(cases, "fw2_025", "strong_decoy")
    verdict, _confidence, reason = tuned_rule_verdict(case)
    assert verdict != "YES"
    assert reason


def test_rules_abstain_when_decisive_attack_evidence_is_removed(cases):
    case = _case(cases, "fw2_001", "decisive_evidence_removed")
    verdict, confidence, _reason = tuned_rule_verdict(case)
    assert verdict == "INSUFFICIENT"
    assert confidence == 0.5


def test_no_evidence_starved_attack_still_triggers_rule_attack(cases):
    starved_attacks = [
        case for case in cases
        if case["variant"] == "decisive_evidence_removed"
        and case["ground_truth"]["latent_incident_label"] == "ATTACK"
    ]
    assert len(starved_attacks) == 24
    assert all(tuned_rule_verdict(case)[0] != "YES" for case in starved_attacks)


def test_rules_resolve_explicit_authorized_maintenance(cases):
    case = _case(cases, "fw2_025", "canonical")
    verdict, confidence, _reason = tuned_rule_verdict(case)
    assert verdict == "NO"
    assert confidence >= 0.85


def test_run_baselines_respects_training_test_boundary(cases):
    records = run_baselines(cases)
    by_model = {}
    for record in records:
        by_model.setdefault(record.model, []).append(record)

    assert len(by_model["always_attack"]) == 480
    assert len(by_model["always_benign"]) == 480
    assert len(by_model["tuned_rules"]) == 480
    assert len(by_model["logistic_regression_events_alerts"]) == 360
    assert len(by_model["gradient_boosted_trees_events_alerts"]) == 360
    assert {record.split for record in by_model["logistic_regression_events_alerts"]} == {"test"}


def test_summary_uses_test_partition_and_independent_base_count(cases):
    summary = summarize_predictions(run_baselines(cases))
    for metrics in summary["models"].values():
        assert metrics["case_variants"] == 360
        assert metrics["base_cases"] == 36
        assert 0 <= metrics["balanced_accuracy"] <= 1


def test_write_results_are_machine_readable(cases, tmp_path):
    prediction_path = tmp_path / "predictions.jsonl"
    summary_path = tmp_path / "summary.json"
    records = run_baselines(cases)
    summary = write_baseline_results(
        records,
        predictions_path=prediction_path,
        summary_path=summary_path,
    )
    first = json.loads(prediction_path.read_text().splitlines()[0])

    assert first["case_id"]
    assert first["base_case_id"]
    assert summary["prediction_records"] == 2160
    assert json.loads(summary_path.read_text())["baseline_version"] == "warrant-baselines-v1.0"
