from __future__ import annotations

import csv
import copy
import json
from pathlib import Path

import pytest

from app.evaluation.warrant_annotations import ANNOTATION_AXES, export_annotation_package
from app.evaluation.warrant_human import analyze_human_annotations
from app.evaluation.warrant_human import export_adjudication_package
from app.evaluation.warrant_human import _binary_warrant_metrics
from app.evaluation.warrant_human import _human_primary_endpoint


def _case() -> dict:
    return {
        "case_id": "case_1",
        "events": [{"event_id": "evt_1", "action": "login", "user": "u1"}],
        "baselines": {},
    }


def _record(
    condition: str = "llm_events_plus_alerts",
    *,
    predicted_verdict: str = "YES",
) -> dict:
    claim = {
        "claim_id": "c1",
        "claim_type": "observation",
        "decisive": False,
        "cited_event_ids": ["evt_1"],
    }
    return {
        "run_id": "run_1",
        "case_id": "case_1",
        "base_case_id": "base_1",
        "family": "test",
        "split": "test",
        "variant": "canonical",
        "condition": condition,
        "repetition": 0,
        "generation_group": "alerts_visible_shared",
        "requested_model": "model",
        "expected_verdict": "YES",
        "operational_status": "valid",
        "predicted_verdict": predicted_verdict,
        "generator_response_sha256": "response_hash",
        "generator": {
            "parsed_output": {
                "verdict": "YES",
                "suspect": "u1",
                "evidence_for": ["evt_1"],
                "evidence_against": [],
                "missing_evidence": [],
                "claims": [claim],
            }
        },
        "mechanical_warrant": {
            "assessments": [{
                "claim_id": "c1",
                "overall_label": "SUPPORTED",
                "axes": [
                    {"axis": axis, "label": "SUPPORTED"}
                    for axis in ANNOTATION_AXES
                ],
            }]
        },
    }


def _complete_csv(
    source: Path,
    target: Path,
    annotator_id: str,
    *,
    overall_label: str = "SUPPORTED",
    materiality_decisive: str = "false",
) -> None:
    with source.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    for row in rows:
        row["annotator_id"] = annotator_id
        row["overall_label"] = overall_label
        row["materiality_decisive"] = materiality_decisive
        row["rationale"] = "The cited event directly supports the claim."
        row["missing_evidence"] = ""
        row["adjudication_needed"] = "false"
        row["elapsed_seconds"] = "30.0"
        for axis in ANNOTATION_AXES:
            row[f"axis_{axis}"] = "SUPPORTED"
    with target.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _completed_inputs(tmp_path: Path) -> tuple[Path, Path, Path, Path, Path]:
    package = tmp_path / "package"
    record = _record()
    abstained = copy.deepcopy(record)
    abstained["condition"] = "generator_verifier_abstention"
    export_annotation_package(
        [record, abstained], {"case_1": _case()}, package, sample_size=1, seed=7
    )
    records_path = tmp_path / "records.jsonl"
    records_path.write_text(json.dumps(record) + "\n" + json.dumps(abstained) + "\n")
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    final = tmp_path / "final.csv"
    _complete_csv(package / "blind" / "annotator_1.csv", first, "reviewer-a")
    _complete_csv(package / "blind" / "annotator_2.csv", second, "reviewer-b")
    _complete_csv(package / "blind" / "adjudication.csv", final, "reviewer-c")
    return package, records_path, first, second, final


def test_human_analysis_validates_and_compares_mechanical_labels(tmp_path: Path) -> None:
    package, records, first, second, final = _completed_inputs(tmp_path)

    analysis = analyze_human_annotations(package, records, first, second, final)

    assert analysis["sample"]["selected_claims"] == 1
    assert analysis["inter_rater"]["overall"]["agreement"] == 1.0
    assert analysis["mechanical_validation"]["overall"]["agreement"] == 1.0
    assert analysis["mechanical_validation"]["materially_unwarranted_flag"][
        "counts"
    ] == {"tn": 1}
    agreement_ci = analysis["bootstrap"]["metrics"][
        "mechanical_overall_agreement"
    ]["confidence_interval"]
    assert agreement_ci == [1.0, 1.0]
    assert analysis["annotation_timing"]["annotator_1"] == {
        "items": 1,
        "total_hours": 30.0 / 3600.0,
        "median_seconds_per_item": 30.0,
        "mean_seconds_per_item": 30.0,
    }


def test_human_labels_replace_proxy_in_primary_safety_contrast(tmp_path: Path) -> None:
    package = tmp_path / "package"
    reference = _record()
    intervention = _record(
        "generator_verifier_abstention", predicted_verdict="INSUFFICIENT"
    )
    intervention["operational_status"] = "valid_abstained"
    records = [reference, intervention]
    export_annotation_package(
        records, {"case_1": _case()}, package, sample_size=1, seed=7
    )
    records_path = tmp_path / "records.jsonl"
    records_path.write_text("".join(json.dumps(row) + "\n" for row in records))
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"
    final = tmp_path / "final.csv"
    for source, target, reviewer in (
        (package / "blind" / "annotator_1.csv", first, "reviewer-a"),
        (package / "blind" / "annotator_2.csv", second, "reviewer-b"),
        (package / "blind" / "adjudication.csv", final, "reviewer-c"),
    ):
        _complete_csv(
            source,
            target,
            reviewer,
            overall_label="INSUFFICIENT",
            materiality_decisive="true",
        )

    analysis = analyze_human_annotations(
        package, records_path, first, second, final
    )

    endpoint = analysis["human_primary_endpoint"]
    assert endpoint["condition_estimates"]["llm_events_plus_alerts"][
        "surfaced_unwarranted_decisive_claims_per_base_case"
    ] == 1.0
    assert endpoint["condition_estimates"]["generator_verifier_abstention"][
        "surfaced_unwarranted_decisive_claims_per_base_case"
    ] == 0.0
    assert endpoint["contrast_intervention_minus_reference"] == {
        "estimate": -1.0,
        "confidence_interval": [-1.0, -1.0],
    }


def test_human_analysis_requires_three_distinct_reviewers(tmp_path: Path) -> None:
    package, records, first, second, final = _completed_inputs(tmp_path)
    _complete_csv(package / "blind" / "adjudication.csv", final, "reviewer-a")

    with pytest.raises(ValueError, match="distinct IDs"):
        analyze_human_annotations(package, records, first, second, final)


def test_human_analysis_rejects_changed_annotation_guide(tmp_path: Path) -> None:
    package, records, first, second, final = _completed_inputs(tmp_path)
    guide = package / "blind" / "ANNOTATION_GUIDE.md"
    guide.write_text(guide.read_text() + "\nchanged after review\n")

    with pytest.raises(ValueError, match="guide hash"):
        analyze_human_annotations(package, records, first, second, final)


def test_human_analysis_rejects_missing_active_time(tmp_path: Path) -> None:
    package, records, first, second, final = _completed_inputs(tmp_path)
    with first.open(newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames
        rows = list(reader)
    rows[0]["elapsed_seconds"] = ""
    with first.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    with pytest.raises(ValueError, match="invalid elapsed_seconds"):
        analyze_human_annotations(package, records, first, second, final)


def test_materially_unwarranted_flag_requires_decisive_claim() -> None:
    human = {
        "item": {
            "overall_label": "INSUFFICIENT",
            "materiality_decisive": "false",
        }
    }
    mechanical = {
        "item": {
            "overall_label": "INSUFFICIENT",
            "materiality_decisive": "false",
        }
    }
    metrics = _binary_warrant_metrics(human, mechanical, {"item": 1.0})
    assert metrics["counts"] == {"tn": 1}


def test_human_primary_endpoint_retains_design_weights_and_cluster_mean() -> None:
    keys = [
        {
            "annotation_id": f"ann_{index}",
            "case_id": f"case_{index}",
            "generator_response_sha256": f"hash_{index}",
            "expected_verdict": "YES",
            "generation_group": "alerts_visible_shared",
            "claim_type": "decision",
            "generator_decisive": True,
        }
        for index in (1, 2)
    ]
    final = {
        key["annotation_id"]: {
            "overall_label": "INSUFFICIENT",
            "materiality_decisive": "true",
        }
        for key in keys
    }
    records = []
    for index in (1, 2):
        common = {
            "case_id": f"case_{index}",
            "base_case_id": f"base_{index}",
            "generator_response_sha256": f"hash_{index}",
            "operational_status": "valid",
        }
        records.append({
            **common,
            "condition": "llm_events_plus_alerts",
            "predicted_verdict": "YES",
        })
        records.append({
            **common,
            "condition": "generator_verifier_abstention",
            "predicted_verdict": "INSUFFICIENT" if index == 1 else "YES",
        })

    endpoint = _human_primary_endpoint(
        keys,
        final,
        records,
        {"ann_1": 2.0, "ann_2": 1.0},
        resamples=20,
        seed=3,
    )

    assert endpoint["condition_estimates"]["llm_events_plus_alerts"][
        "surfaced_unwarranted_decisive_claims_per_base_case"
    ] == 1.5
    assert endpoint["condition_estimates"]["generator_verifier_abstention"][
        "surfaced_unwarranted_decisive_claims_per_base_case"
    ] == 0.5
    assert endpoint["contrast_intervention_minus_reference"]["estimate"] == -1.0


def test_adjudication_export_shows_reviews_without_reviewer_ids(tmp_path: Path) -> None:
    package, _, first, second, _ = _completed_inputs(tmp_path)
    _complete_csv(
        package / "blind" / "annotator_2.csv",
        second,
        "reviewer-b",
        overall_label="INSUFFICIENT",
    )
    output = tmp_path / "adjudication"

    manifest = export_adjudication_package(package, first, second, output)

    html = (output / "review.html").read_text()
    assert manifest["items_requiring_adjudication"] == 1
    assert 'value="adjudication"' in html
    assert "reviewer-a" not in html
    assert "reviewer-b" not in html
    assert (output / "adjudication.csv").exists()
    assert (output / "ANNOTATION_GUIDE.md").read_bytes() == (
        package / "blind" / "ANNOTATION_GUIDE.md"
    ).read_bytes()
