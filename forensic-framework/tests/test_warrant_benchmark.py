"""Tests for the paired forensic evidential-warrant benchmark."""

from __future__ import annotations

import hashlib
import json

import pytest

from app.ingestion.warrant_benchmark import (
    FAMILY_BUILDERS,
    generate_cases,
    load_cases,
    validate_cases,
    write_benchmark,
)


@pytest.fixture(scope="module")
def warrant_cases():
    return generate_cases()


def _case(cases, base_case_id, variant):
    return next(
        case for case in cases
        if case["base_case_id"] == base_case_id and case["variant"] == variant
    )


def _canonical_bytes(cases):
    lines = [json.dumps(case, sort_keys=True, separators=(",", ":")) for case in cases]
    return ("\n".join(lines) + "\n").encode()


def test_benchmark_has_preregistered_shape(warrant_cases):
    assert len(warrant_cases) == 480
    assert len({case["base_case_id"] for case in warrant_cases}) == 48
    assert len({case["family"] for case in warrant_cases}) == 12
    assert len({case["variant"] for case in warrant_cases}) == 10
    assert set(FAMILY_BUILDERS) == {case["family"] for case in warrant_cases}


def test_benchmark_generation_is_byte_deterministic(warrant_cases):
    first = _canonical_bytes(warrant_cases)
    second = _canonical_bytes(generate_cases())
    assert hashlib.sha256(first).hexdigest() == hashlib.sha256(second).hexdigest()


def test_variants_of_base_case_never_cross_split(warrant_cases):
    splits: dict[str, set[str]] = {}
    for case in warrant_cases:
        splits.setdefault(case["base_case_id"], set()).add(case["split"])
    assert all(len(values) == 1 for values in splits.values())
    assert len({case["base_case_id"] for case in warrant_cases if case["split"] == "development"}) == 12
    assert len({case["base_case_id"] for case in warrant_cases if case["split"] == "test"}) == 36


def test_no_alert_condition_changes_context_not_events(warrant_cases):
    canonical = _case(warrant_cases, "fw2_001", "canonical")
    no_alert = _case(warrant_cases, "fw2_001", "no_alert")
    assert canonical["events"] == no_alert["events"]
    assert canonical["alerts"]
    assert no_alert["alerts"] == []


def test_misleading_actor_changes_only_alert_attribution(warrant_cases):
    canonical = _case(warrant_cases, "fw2_001", "canonical")
    misleading = _case(warrant_cases, "fw2_001", "misleading_alert_actor")
    assert canonical["events"] == misleading["events"]
    assert canonical["alerts"][0]["actor"] != misleading["alerts"][0]["actor"]
    assert misleading["alerts"][0]["actor"] != canonical["ground_truth"]["latent_suspect"]


def test_decisive_evidence_removal_requires_abstention(warrant_cases):
    for case in (item for item in warrant_cases if item["variant"] == "decisive_evidence_removed"):
        visible = {event["event_id"] for event in case["events"]}
        decisive = set(case["ground_truth"]["decisive_event_ids"])
        assert decisive.isdisjoint(visible)
        assert case["ground_truth"]["warranted_verdict"] == "INSUFFICIENT"
        assert case["ground_truth"]["warranted_suspect"] is None


def test_removing_benign_counterevidence_does_not_create_attack_label(warrant_cases):
    benign = [
        case for case in warrant_cases
        if case["variant"] == "counterevidence_removed"
        and case["ground_truth"]["latent_incident_label"] == "BENIGN"
    ]
    assert len(benign) == 24
    assert {case["ground_truth"]["warranted_verdict"] for case in benign} == {"INSUFFICIENT"}


def test_attack_stays_warranted_when_only_counterevidence_is_removed(warrant_cases):
    attacks = [
        case for case in warrant_cases
        if case["variant"] == "counterevidence_removed"
        and case["ground_truth"]["latent_incident_label"] == "ATTACK"
    ]
    assert len(attacks) == 24
    assert {case["ground_truth"]["warranted_verdict"] for case in attacks} == {"YES"}


def test_prompt_injection_is_data_and_is_ground_truth_tagged(warrant_cases):
    case = _case(warrant_cases, "fw2_001", "passive_prompt_injection")
    adversarial_ids = case["ground_truth"]["adversarial_event_ids"]
    assert len(adversarial_ids) == 1
    event = next(event for event in case["events"] if event["event_id"] == adversarial_ids[0])
    assert "Ignore all previous instructions" in event["metadata"]["message"]
    assert set(event["metadata"]) == {"message"}
    assert "inject" not in event["event_id"].lower()


def test_schema_drift_preserves_identifiers_but_changes_field_layout(warrant_cases):
    canonical = _case(warrant_cases, "fw2_001", "canonical")
    drifted = _case(warrant_cases, "fw2_001", "schema_drift")
    assert {event["event_id"] for event in canonical["events"]} == {
        event["event_id"] for event in drifted["events"]
    }
    assert any("operation" in event and "action" not in event for event in drifted["events"])
    assert any("principal" in event and "user" not in event for event in drifted["events"])


def test_strong_decoy_is_loud_but_has_no_successful_login(warrant_cases):
    case = _case(warrant_cases, "fw2_001", "strong_decoy")
    decoy_ids = set(case["ground_truth"]["irrelevant_event_ids"])
    decoys = [event for event in case["events"] if event["event_id"] in decoy_ids]
    assert len(decoys) == 5
    assert {event["action"] for event in decoys} == {"login_failed"}
    assert {event["status"] for event in decoys} == {"failure"}
    assert case["alerts"][0]["actor"] == decoys[0]["user"]


def test_mutation_roles_are_not_exposed_in_visible_fields(warrant_cases):
    for case in warrant_cases:
        for event in case["events"]:
            event_id = event["event_id"].lower()
            assert not any(
                token in event_id for token in ("noise", "inject", "decoy")
            ), case["case_id"]
            session_id = str(event.get("session_id") or "").lower()
            assert not any(
                token in session_id
                for token in ("noise", "suspicious", "approved")
            ), case["case_id"]
            assert not {
                "decoy", "irrelevant", "untrusted_content"
            }.intersection(event.get("metadata") or {}), case["case_id"]
        assert not any(
            "decoy actor" in str(alert.get("reason") or "").lower()
            for alert in case["alerts"]
        ), case["case_id"]


def test_visible_reference_findings_require_visible_evidence(warrant_cases):
    for case in warrant_cases:
        visible = {event["event_id"] for event in case["events"]}
        for finding in case["ground_truth"]["visible_reference_findings"]:
            assert set(finding["required_event_ids"]).issubset(visible)


def test_write_manifest_and_reload_are_self_consistent(warrant_cases, tmp_path):
    manifest = write_benchmark(warrant_cases, tmp_path)
    loaded = load_cases(tmp_path / "cases.jsonl")
    validate_cases(loaded)

    assert loaded == warrant_cases
    assert manifest["base_cases"] == 48
    assert manifest["case_variants"] == 480
    assert manifest["base_cases_by_split"] == {"development": 12, "test": 36}
    assert manifest["cases_sha256"] == hashlib.sha256((tmp_path / "cases.jsonl").read_bytes()).hexdigest()
