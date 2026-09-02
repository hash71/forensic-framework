"""Tests for blinded deterministic warrant annotation exports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from app.evaluation.warrant_annotations import (
    build_annotation_items,
    export_annotation_package,
    select_stratified_ids,
)


def _case() -> dict:
    return {
        "case_id": "case_1",
        "events": [{"event_id": "evt_1", "action": "login", "user": "u1"}],
        "baselines": {"u1": {}},
    }


def _record(condition: str, response_hash: str = "hash_shared") -> dict:
    return {
        "run_id": "run_1",
        "case_id": "case_1",
        "base_case_id": "base_1",
        "family": "credential_compromise",
        "split": "development",
        "variant": "canonical",
        "condition": condition,
        "repetition": 0,
        "generation_group": "alerts_visible_shared",
        "requested_model": "hidden-model",
        "expected_verdict": "YES",
        "operational_status": "valid",
        "generator_response_sha256": response_hash,
        "generator": {
            "parser_status": "valid",
            "parsed_output": {
                "verdict": "YES",
                "suspect": "u1",
                "evidence_for": ["evt_1"],
                "evidence_against": [],
                "missing_evidence": [],
                "claims": [
                    {
                        "claim_id": "c1",
                        "claim_type": "observation",
                        "decisive": True,
                        "cited_event_ids": ["evt_1"],
                    }
                ],
            },
        },
    }


def test_shared_generation_is_exported_once_and_blind_item_hides_condition():
    records = [_record("llm_events_plus_alerts"), _record("generator_verifier")]
    blind, keys, failures = build_annotation_items(records, {"case_1": _case()})

    assert len(blind) == 1
    assert len(keys) == 1
    assert failures == []
    assert "condition" not in json.dumps(blind[0])
    assert keys[0]["conditions_sharing_generation"] == [
        "generator_verifier",
        "llm_events_plus_alerts",
    ]


def test_stratified_selection_is_deterministic():
    keys = []
    for index in range(20):
        keys.append({
            "annotation_id": f"ann_{index}",
            "expected_verdict": "YES" if index % 2 else "NO",
            "generation_group": "events" if index % 3 else "alerts",
            "claim_type": "decision" if index % 5 else "observation",
            "generator_decisive": bool(index % 2),
        })
    first = select_stratified_ids(keys, sample_size=8, seed=17)
    second = select_stratified_ids(list(reversed(keys)), sample_size=8, seed=17)

    assert first == second
    assert len(first) == 8


def test_export_writes_two_blank_annotator_templates(tmp_path: Path):
    manifest = export_annotation_package(
        [_record("llm_events_plus_alerts")],
        {"case_1": _case()},
        tmp_path,
        sample_size=10,
        seed=3,
        provenance={"source_run_id": "run_1"},
    )

    assert manifest["selected_claims"] == 1
    assert manifest["provenance"] == {"source_run_id": "run_1"}
    assert sum(manifest["population_stratum_counts"].values()) == 1
    assert sum(manifest["stratum_counts"].values()) == 1
    assert (tmp_path / "blind" / "items.jsonl").exists()
    assert (tmp_path / "blind" / "ANNOTATION_GUIDE.md").exists()
    assert (tmp_path / "blind" / "review.html").exists()
    guide = (tmp_path / "blind" / "ANNOTATION_GUIDE.md").read_text()
    assert manifest["annotation_guide_sha256"]
    assert "Do the cited events" in guide
    with (tmp_path / "blind" / "annotator_1.csv").open() as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["annotation_id"].startswith("ann_")
    assert rows[0]["overall_label"] == ""
    review_html = (tmp_path / "blind" / "review.html").read_text()
    assert "hidden-model" not in review_html
    assert 'value="adjudication"' not in review_html
    assert "const encoded = 'ey" in review_html
    assert '/[",\\n]/.test(s)' in review_html
    assert "rows.join('\\n')+'\\n'" in review_html
    assert '/[",\n]/.test(s)' not in review_html
    assert "rows.join('\n')+'\n'" not in review_html


def test_annotators_receive_different_deterministic_orders(tmp_path: Path):
    records = [
        _record("llm_events_plus_alerts", response_hash=f"hash_{index}")
        for index in range(12)
    ]
    export_annotation_package(
        records,
        {"case_1": _case()},
        tmp_path,
        sample_size=12,
        seed=19,
    )
    with (tmp_path / "blind" / "annotator_1.csv").open() as handle:
        first = [row["annotation_id"] for row in csv.DictReader(handle)]
    with (tmp_path / "blind" / "annotator_2.csv").open() as handle:
        second = [row["annotation_id"] for row in csv.DictReader(handle)]

    assert set(first) == set(second)
    assert first != second
