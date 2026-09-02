from __future__ import annotations

import csv
import hashlib
import json

import pytest

from app.evaluation.warrant_annotations import ANNOTATION_AXES
from app.evaluation.warrant_simulated import (
    consensus_reviews,
    deterministic_batches,
    export_targeted_review_package,
    simulated_system_prompt,
    validate_simulated_response,
    reviewer_batch_config,
)


def _item(annotation_id: str, payload: str = "x") -> dict:
    return {
        "annotation_id": annotation_id,
        "case_display_id": "case_blind",
        "claim": {"text": payload},
        "cited_events": [],
        "visible_events": [],
        "visible_baselines": {},
        "investigation_context": {},
    }


def _review(annotation_id: str, label: str = "SUPPORTED") -> dict:
    return {
        "annotation_id": annotation_id,
        "overall_label": label,
        "materiality_decisive": label != "SUPPORTED",
        "axes": {axis: label for axis in ANNOTATION_AXES},
        "rationale": "The cited fields determine the label.",
        "missing_evidence": "" if label == "SUPPORTED" else "Corroboration.",
    }


def test_prompt_explicitly_forbids_boolean_axis_labels() -> None:
    prompt = simulated_system_prompt("strict_evidentiary")
    assert "never true or false" in prompt
    assert '"actor":"INSUFFICIENT"' in prompt
    assert "not a real human expert" in prompt


def test_response_validation_accepts_only_frozen_schema() -> None:
    accepted = validate_simulated_response(
        {"reviews": [_review("ann_1")]}, ["ann_1"]
    )
    assert accepted[0]["overall_label"] == "SUPPORTED"
    assert accepted[0]["schema_normalizations"] == []

    invalid = _review("ann_1")
    invalid["axes"]["actor"] = True
    with pytest.raises(ValueError, match="invalid axis label"):
        validate_simulated_response({"reviews": [invalid]}, ["ann_1"])

    with pytest.raises(ValueError, match="reordered"):
        validate_simulated_response(
            {"reviews": [_review("ann_2"), _review("ann_1")]},
            ["ann_1", "ann_2"],
        )

    with pytest.raises(ValueError, match="JSON object"):
        validate_simulated_response({"reviews": ["not-an-object"]}, ["ann_1"])


def test_missing_evidence_has_auditable_narrow_normalization() -> None:
    review = _review("ann_1")
    review["missing_evidence"] = ["Policy", "Session linkage"]
    accepted = validate_simulated_response({"reviews": [review]}, ["ann_1"])[0]
    assert accepted["missing_evidence"] == "Policy; Session linkage"
    assert accepted["schema_normalizations"] == [
        "missing_evidence:string_list_joined"
    ]


def test_batches_are_deterministic_and_bounded() -> None:
    items = [_item(f"ann_{index}", "x" * 30) for index in range(9)]
    first = deterministic_batches(
        items, reviewer_id="sim_a", max_items=3, max_chars=1000
    )
    second = deterministic_batches(
        list(reversed(items)), reviewer_id="sim_a", max_items=3, max_chars=1000
    )
    assert [[item["annotation_id"] for item in batch] for batch in first] == [
        [item["annotation_id"] for item in batch] for batch in second
    ]
    assert all(len(batch) <= 3 for batch in first)


def test_reviewer_batch_override_is_explicit_and_non_mutating() -> None:
    default = {
        "max_items": 8,
        "max_chars": 32000,
        "max_tokens": 4096,
        "retry_attempts": 2,
    }
    merged = reviewer_batch_config(default, {"batch": {"max_items": 1}})
    assert merged["max_items"] == 1
    assert default["max_items"] == 8


def test_consensus_is_field_level_majority_not_fake_adjudication() -> None:
    reviewers = {
        "sim_a": {"ann_1": _review("ann_1", "SUPPORTED")},
        "sim_b": {"ann_1": _review("ann_1", "INSUFFICIENT")},
        "sim_c": {"ann_1": _review("ann_1", "INSUFFICIENT")},
    }
    consensus, disagreements = consensus_reviews(reviewers, {"ann_1"})
    assert consensus["ann_1"]["overall_label"] == "INSUFFICIENT"
    assert consensus["ann_1"]["materiality_decisive"] == "true"
    assert "overall_label" in disagreements[0]["disagreement_fields"]


def test_targeted_review_export_keeps_selection_basis_out_of_blind_dir(
    tmp_path,
) -> None:
    source = tmp_path / "source"
    blind = source / "blind"
    admin = source / "admin_do_not_share_with_annotators"
    blind.mkdir(parents=True)
    admin.mkdir(parents=True)
    items = [
        {
            **_item(f"ann_{index}"),
            "annotation_export_version": "warrant-annotation-export-v1.2",
        }
        for index in range(3)
    ]
    keys = [
        {
            "annotation_id": f"ann_{index}",
            "expected_verdict": "YES",
            "generation_group": "alerts_visible_shared",
            "claim_type": "observation",
            "generator_decisive": True,
        }
        for index in range(3)
    ]
    items_text = "".join(json.dumps(row) + "\n" for row in items)
    keys_text = "".join(json.dumps(row) + "\n" for row in keys)
    (blind / "items.jsonl").write_text(items_text)
    (admin / "key.jsonl").write_text(keys_text)
    (source / "manifest.json").write_text(json.dumps({
        "annotation_export_version": "warrant-annotation-export-v1.2",
        "items_sha256": hashlib.sha256(items_text.encode()).hexdigest(),
        "admin_key_sha256": hashlib.sha256(keys_text.encode()).hexdigest(),
    }))
    priority = tmp_path / "priority.csv"
    with priority.open("w", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["annotation_id", "ai_consensus_overall", "priority_score"],
        )
        writer.writeheader()
        writer.writerows([
            {
                "annotation_id": "ann_2",
                "ai_consensus_overall": "INSUFFICIENT",
                "priority_score": "10",
            },
            {
                "annotation_id": "ann_0",
                "ai_consensus_overall": "SUPPORTED",
                "priority_score": "8",
            },
        ])

    output = tmp_path / "targeted"
    manifest = export_targeted_review_package(
        source, priority, output, limit=2, seed=9
    )
    assert manifest["selected_claims"] == 2
    assert "cannot estimate population" in manifest["validity_boundary"]
    assert not (output / "blind" / "selection_basis.csv").exists()
    selection = (output / "admin_do_not_share_with_annotators" / "selection_basis.csv")
    assert "INSUFFICIENT" in selection.read_text()
    assert (output / "blind" / "review.html").is_file()
