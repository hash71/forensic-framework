"""Validation and analysis for independent forensic-warrant annotations."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.evaluation.warrant_annotations import (
    ANNOTATION_AXES,
    _write_answer_template,
    _write_review_html,
    annotation_stratum,
)


HUMAN_ANALYSIS_VERSION = "warrant-human-analysis-v1.2"
HUMAN_BOOTSTRAP_RESAMPLES = 10_000
HUMAN_BOOTSTRAP_SEED = 20_260_902
WARRANT_LABELS = {"SUPPORTED", "CONTRADICTED", "INSUFFICIENT", "NOT_APPLICABLE"}
BOOLEAN_LABELS = {"true", "false"}


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


def load_complete_annotations(
    path: Path,
    expected_ids: set[str],
) -> tuple[dict[str, dict[str, str]], str]:
    """Load one completed CSV and reject missing, duplicate, or invalid labels."""

    required = {
        "annotation_id",
        "annotator_id",
        "overall_label",
        "materiality_decisive",
        "rationale",
        "missing_evidence",
        "adjudication_needed",
        "elapsed_seconds",
        *(f"axis_{axis}" for axis in ANNOTATION_AXES),
    }
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        missing_columns = required.difference(reader.fieldnames or [])
        if missing_columns:
            raise ValueError(f"{path}: missing columns {sorted(missing_columns)}")
        rows = [
            {key: (value or "").strip() for key, value in row.items()}
            for row in reader
        ]
    ids = [row["annotation_id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{path}: duplicate annotation_id")
    actual_ids = set(ids)
    if actual_ids != expected_ids:
        raise ValueError(
            f"{path}: annotation-id mismatch; missing={sorted(expected_ids - actual_ids)[:5]}, "
            f"unexpected={sorted(actual_ids - expected_ids)[:5]}"
        )
    annotator_ids = {row["annotator_id"] for row in rows if row["annotator_id"]}
    if len(annotator_ids) != 1 or any(not row["annotator_id"] for row in rows):
        raise ValueError(f"{path}: exactly one non-empty annotator_id is required")
    for row in rows:
        annotation_id = row["annotation_id"]
        if row["overall_label"] not in WARRANT_LABELS:
            raise ValueError(f"{path}: invalid overall label for {annotation_id}")
        if row["materiality_decisive"] not in BOOLEAN_LABELS:
            raise ValueError(f"{path}: invalid materiality for {annotation_id}")
        if row["adjudication_needed"] not in BOOLEAN_LABELS:
            raise ValueError(f"{path}: invalid adjudication flag for {annotation_id}")
        try:
            elapsed_seconds = float(row["elapsed_seconds"])
        except ValueError as exc:
            raise ValueError(
                f"{path}: invalid elapsed_seconds for {annotation_id}"
            ) from exc
        if not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
            raise ValueError(
                f"{path}: elapsed_seconds must be positive for {annotation_id}"
            )
        if not row["rationale"]:
            raise ValueError(f"{path}: rationale required for {annotation_id}")
        for axis in ANNOTATION_AXES:
            if row[f"axis_{axis}"] not in WARRANT_LABELS:
                raise ValueError(
                    f"{path}: invalid {axis} label for {annotation_id}"
                )
    return {row["annotation_id"]: row for row in rows}, next(iter(annotator_ids))


def _reviewer_view(row: dict[str, str]) -> dict[str, Any]:
    return {
        "overall_label": row["overall_label"],
        "materiality_decisive": row["materiality_decisive"],
        "axis_labels": {
            axis: row[f"axis_{axis}"] for axis in ANNOTATION_AXES
        },
        "rationale": row["rationale"],
        "missing_evidence": row["missing_evidence"],
    }


def _timing_summary(rows: dict[str, dict[str, str]]) -> dict[str, float]:
    values = [float(row["elapsed_seconds"]) for row in rows.values()]
    return {
        "items": len(values),
        "total_hours": sum(values) / 3600.0,
        "median_seconds_per_item": statistics.median(values),
        "mean_seconds_per_item": statistics.fmean(values),
    }


def export_adjudication_package(
    package_dir: Path,
    annotator_1_path: Path,
    annotator_2_path: Path,
    output_dir: Path,
) -> dict[str, Any]:
    """Create a blind adjudication UI after both independent reviews freeze."""

    items = _read_jsonl(package_dir / "blind" / "items.jsonl")
    expected_ids = {item["annotation_id"] for item in items}
    first, first_id = load_complete_annotations(annotator_1_path, expected_ids)
    second, second_id = load_complete_annotations(annotator_2_path, expected_ids)
    if first_id == second_id:
        raise ValueError("independent annotators need distinct IDs")
    with (package_dir / "blind" / "adjudication.csv").open(newline="") as handle:
        order = [row["annotation_id"] for row in csv.DictReader(handle)]
    if len(order) != len(expected_ids) or set(order) != expected_ids:
        raise ValueError("adjudication template does not match blind items")

    fields = [
        "overall_label",
        "materiality_decisive",
        *(f"axis_{axis}" for axis in ANNOTATION_AXES),
    ]
    prior_reviews = {}
    for annotation_id in order:
        prior_reviews[annotation_id] = {
            "reviewer_1": _reviewer_view(first[annotation_id]),
            "reviewer_2": _reviewer_view(second[annotation_id]),
            "disagreement_fields": [
                field
                for field in fields
                if first[annotation_id][field] != second[annotation_id][field]
            ],
        }
    output_dir.mkdir(parents=True, exist_ok=True)
    source_guide = package_dir / "blind" / "ANNOTATION_GUIDE.md"
    output_guide = output_dir / "ANNOTATION_GUIDE.md"
    output_guide.write_bytes(source_guide.read_bytes())
    _write_answer_template(output_dir / "adjudication.csv", order)
    _write_review_html(
        output_dir / "review.html",
        items,
        {"adjudication": order},
        prior_reviews=prior_reviews,
    )
    manifest = {
        "human_analysis_version": HUMAN_ANALYSIS_VERSION,
        "source_annotation_manifest_sha256": _sha256_bytes(
            (package_dir / "manifest.json").read_bytes()
        ),
        "annotator_1_csv_sha256": _sha256_bytes(annotator_1_path.read_bytes()),
        "annotator_2_csv_sha256": _sha256_bytes(annotator_2_path.read_bytes()),
        "annotation_guide_sha256": _sha256_bytes(output_guide.read_bytes()),
        "reviewer_id_sha256": {
            "annotator_1": hashlib.sha256(first_id.encode()).hexdigest(),
            "annotator_2": hashlib.sha256(second_id.encode()).hexdigest(),
        },
        "item_count": len(order),
        "items_requiring_adjudication": sum(
            bool(review["disagreement_fields"])
            for review in prior_reviews.values()
        ),
        "identity_policy": (
            "reviewer IDs and system-condition metadata are omitted from the "
            "adjudicator interface"
        ),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def _cohen_kappa(
    left: list[str],
    right: list[str],
    weights: list[float] | None = None,
) -> float | None:
    if len(left) != len(right) or not left:
        raise ValueError("kappa inputs must be non-empty and equally sized")
    effective = weights or [1.0] * len(left)
    if len(effective) != len(left) or any(weight <= 0 for weight in effective):
        raise ValueError("kappa weights must be positive and aligned")
    total = sum(effective)
    observed = sum(
        weight for a, b, weight in zip(left, right, effective) if a == b
    ) / total
    categories = set(left).union(right)
    left_mass = Counter()
    right_mass = Counter()
    for a, b, weight in zip(left, right, effective):
        left_mass[a] += weight
        right_mass[b] += weight
    expected = sum(
        (left_mass[label] / total) * (right_mass[label] / total)
        for label in categories
    )
    if math.isclose(expected, 1.0):
        return None
    return (observed - expected) / (1.0 - expected)


def _agreement(
    left: dict[str, dict[str, str]],
    right: dict[str, dict[str, str]],
    field: str,
    design_weights: dict[str, float],
) -> dict[str, Any]:
    ids = sorted(left)
    a = [left[item][field] for item in ids]
    b = [right[item][field] for item in ids]
    weights = [design_weights[item] for item in ids]
    agreements = [one == two for one, two in zip(a, b)]
    weighted_total = sum(weights)
    labels = sorted(set(a).union(b))
    left_counts = Counter(a)
    right_counts = Counter(b)
    left_weighted = Counter()
    right_weighted = Counter()
    agreement_counts = Counter()
    agreement_weighted = Counter()
    for left_label, right_label, weight in zip(a, b, weights):
        left_weighted[left_label] += weight
        right_weighted[right_label] += weight
        if left_label == right_label:
            agreement_counts[left_label] += 1
            agreement_weighted[left_label] += weight
    return {
        "n": len(ids),
        "agreement": sum(agreements) / len(ids),
        "design_weighted_agreement": sum(
            weight for matches, weight in zip(agreements, weights) if matches
        ) / weighted_total,
        "cohen_kappa": _cohen_kappa(a, b),
        "design_weighted_cohen_kappa": _cohen_kappa(a, b, weights),
        "disagreements": len(ids) - sum(agreements),
        "label_prevalence": {
            "reviewer_1": {
                label: left_counts[label] / len(ids) for label in labels
            },
            "reviewer_2": {
                label: right_counts[label] / len(ids) for label in labels
            },
            "design_weighted_reviewer_1": {
                label: left_weighted[label] / weighted_total for label in labels
            },
            "design_weighted_reviewer_2": {
                label: right_weighted[label] / weighted_total for label in labels
            },
        },
        "positive_agreement_by_label": {
            label: _safe_ratio(
                2 * agreement_counts[label],
                left_counts[label] + right_counts[label],
            )
            for label in labels
        },
        "design_weighted_positive_agreement_by_label": {
            label: _safe_ratio(
                2 * agreement_weighted[label],
                left_weighted[label] + right_weighted[label],
            )
            for label in labels
        },
    }


def _confusion(
    reference: dict[str, dict[str, str]],
    candidate: dict[str, dict[str, str]],
    field: str,
    design_weights: dict[str, float],
) -> dict[str, Any]:
    raw: Counter[tuple[str, str]] = Counter()
    weighted: Counter[tuple[str, str]] = Counter()
    for annotation_id in sorted(reference):
        pair = (reference[annotation_id][field], candidate[annotation_id][field])
        raw[pair] += 1
        weighted[pair] += design_weights[annotation_id]
    return {
        "rows_are_reference_columns_are_candidate": {
            f"{left}|{right}": count
            for (left, right), count in sorted(raw.items())
        },
        "design_weighted": {
            f"{left}|{right}": round(count, 6)
            for (left, right), count in sorted(weighted.items())
        },
    }


def _safe_ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _binary_warrant_metrics(
    human: dict[str, dict[str, str]],
    mechanical: dict[str, dict[str, str]],
    design_weights: dict[str, float],
) -> dict[str, Any]:
    counts = Counter()
    weighted = Counter()
    unsafe = {"CONTRADICTED", "INSUFFICIENT"}
    for annotation_id, final in human.items():
        human_positive = (
            final["overall_label"] in unsafe
            and final["materiality_decisive"] == "true"
        )
        machine_positive = (
            mechanical[annotation_id]["overall_label"] in unsafe
            and mechanical[annotation_id]["materiality_decisive"] == "true"
        )
        cell = (
            "tp" if human_positive and machine_positive else
            "fn" if human_positive else
            "fp" if machine_positive else
            "tn"
        )
        counts[cell] += 1
        weighted[cell] += design_weights[annotation_id]
    tp, fp, tn, fn = (weighted[name] for name in ("tp", "fp", "tn", "fn"))
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    return {
        "positive_definition": (
            "human overall label is CONTRADICTED or INSUFFICIENT and "
            "materiality_decisive=true"
        ),
        "machine_positive_definition": (
            "mechanical overall label is CONTRADICTED or INSUFFICIENT and "
            "the generated claim is marked decisive"
        ),
        "counts": dict(sorted(counts.items())),
        "design_weighted_counts": {
            key: round(value, 6) for key, value in sorted(weighted.items())
        },
        "design_weighted_precision": precision,
        "design_weighted_recall": recall,
        "design_weighted_specificity": _safe_ratio(tn, tn + fp),
        "design_weighted_f1": (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        ),
    }


def _weighted_agreement_for_ids(
    ids: list[str],
    left: dict[str, dict[str, str]],
    right: dict[str, dict[str, str]],
    field: str,
    design_weights: dict[str, float],
) -> float:
    total = sum(design_weights[item] for item in ids)
    return sum(
        design_weights[item]
        for item in ids
        if left[item][field] == right[item][field]
    ) / total


def _binary_metrics_for_ids(
    ids: list[str],
    human: dict[str, dict[str, str]],
    mechanical: dict[str, dict[str, str]],
    design_weights: dict[str, float],
) -> dict[str, float | None]:
    counts = Counter()
    unsafe = {"CONTRADICTED", "INSUFFICIENT"}
    for annotation_id in ids:
        human_positive = (
            human[annotation_id]["overall_label"] in unsafe
            and human[annotation_id]["materiality_decisive"] == "true"
        )
        machine_positive = (
            mechanical[annotation_id]["overall_label"] in unsafe
            and mechanical[annotation_id]["materiality_decisive"] == "true"
        )
        cell = (
            "tp" if human_positive and machine_positive else
            "fn" if human_positive else
            "fp" if machine_positive else
            "tn"
        )
        counts[cell] += design_weights[annotation_id]
    tp, fp, tn, fn = (counts[name] for name in ("tp", "fp", "tn", "fn"))
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    return {
        "precision": precision,
        "recall": recall,
        "specificity": _safe_ratio(tn, tn + fp),
        "f1": (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        ),
    }


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _bootstrap_human_metrics(
    keys: list[dict[str, Any]],
    first: dict[str, dict[str, str]],
    second: dict[str, dict[str, str]],
    final: dict[str, dict[str, str]],
    mechanical: dict[str, dict[str, str]],
    design_weights: dict[str, float],
    *,
    resamples: int = HUMAN_BOOTSTRAP_RESAMPLES,
    seed: int = HUMAN_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Stratified bootstrap intervals for the human-validation endpoints."""

    if resamples <= 0:
        raise ValueError("human bootstrap requires positive resamples")
    by_stratum: dict[str, list[str]] = {}
    for item in keys:
        by_stratum.setdefault(annotation_stratum(item), []).append(
            item["annotation_id"]
        )
    rng = random.Random(seed)
    sampled: dict[str, list[float]] = defaultdict(list)
    for _ in range(resamples):
        ids = [
            annotation_id
            for stratum in sorted(by_stratum)
            for annotation_id in rng.choices(
                by_stratum[stratum], k=len(by_stratum[stratum])
            )
        ]
        weights = [design_weights[item] for item in ids]
        first_overall = [first[item]["overall_label"] for item in ids]
        second_overall = [second[item]["overall_label"] for item in ids]
        final_overall = [final[item]["overall_label"] for item in ids]
        mechanical_overall = [mechanical[item]["overall_label"] for item in ids]
        values: dict[str, float | None] = {
            "inter_rater_overall_agreement": _weighted_agreement_for_ids(
                ids, first, second, "overall_label", design_weights
            ),
            "inter_rater_overall_kappa": _cohen_kappa(
                first_overall, second_overall, weights
            ),
            "mechanical_overall_agreement": _weighted_agreement_for_ids(
                ids, final, mechanical, "overall_label", design_weights
            ),
            "mechanical_overall_kappa": _cohen_kappa(
                final_overall, mechanical_overall, weights
            ),
            "mechanical_materiality_agreement": _weighted_agreement_for_ids(
                ids, final, mechanical, "materiality_decisive", design_weights
            ),
        }
        binary = _binary_metrics_for_ids(ids, final, mechanical, design_weights)
        values.update({f"materially_unwarranted_{key}": value for key, value in binary.items()})
        for name, value in values.items():
            if value is not None:
                sampled[name].append(float(value))

    return {
        "method": (
            "percentile bootstrap resampling claims with replacement within "
            "each fixed sampling stratum; inverse sampling-fraction weights retained"
        ),
        "confidence_level": 0.95,
        "resamples": resamples,
        "seed": seed,
        "metrics": {
            name: {
                "confidence_interval": [
                    _quantile(values, 0.025),
                    _quantile(values, 0.975),
                ],
                "effective_resamples": len(values),
            }
            for name, values in sorted(sampled.items())
            if values
        },
    }


def _human_primary_endpoint(
    keys: list[dict[str, Any]],
    final: dict[str, dict[str, str]],
    records: list[dict[str, Any]],
    design_weights: dict[str, float],
    *,
    reference: str = "llm_events_plus_alerts",
    intervention: str = "generator_verifier_abstention",
    resamples: int = HUMAN_BOOTSTRAP_RESAMPLES,
    seed: int = HUMAN_BOOTSTRAP_SEED + 1,
) -> dict[str, Any]:
    """Estimate the primary contrast from sampled, adjudicated claim labels.

    The annotation population deduplicates byte-identical generator responses.
    A sampled claim is therefore joined back to every condition/repetition that
    reused that response. Inverse sampling-fraction weights estimate the claim
    population, while delivery remains a record-level property of each policy.
    """

    if resamples <= 0:
        raise ValueError("human primary-endpoint bootstrap requires positive resamples")
    conditions = (reference, intervention)
    base_cases = sorted({record["base_case_id"] for record in records})
    if not base_cases:
        raise ValueError("human primary endpoint requires records")
    record_counts: dict[str, Counter[str]] = {
        condition: Counter(
            record["base_case_id"]
            for record in records
            if record["condition"] == condition
        )
        for condition in conditions
    }
    for condition in conditions:
        missing = set(base_cases).difference(record_counts[condition])
        if missing:
            raise ValueError(
                f"human primary endpoint lacks {condition} records for "
                f"{sorted(missing)[:5]}"
            )

    records_by_response: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        response_hash = record.get("generator_response_sha256")
        if response_hash:
            records_by_response[(record["case_id"], response_hash)].append(record)

    # A contribution is already normalized by the number of condition records
    # within its base-case cluster; the final estimand averages these clusters.
    contributions: dict[str, dict[str, Counter[str]]] = {}
    relevant_ids: set[str] = set()
    for key in keys:
        annotation_id = key["annotation_id"]
        by_condition = {condition: Counter() for condition in conditions}
        matched = records_by_response.get(
            (key["case_id"], key["generator_response_sha256"]), []
        )
        for record in matched:
            condition = record["condition"]
            if condition not in by_condition:
                continue
            relevant_ids.add(annotation_id)
            delivered = (
                record["operational_status"].startswith("valid")
                and record.get("predicted_verdict") != "INSUFFICIENT"
            )
            if delivered:
                base_case_id = record["base_case_id"]
                by_condition[condition][base_case_id] += (
                    design_weights[annotation_id]
                    / record_counts[condition][base_case_id]
                )
        contributions[annotation_id] = by_condition

    if not relevant_ids:
        raise ValueError("annotation sample contains no primary-endpoint claims")
    unsafe = {
        annotation_id: (
            final[annotation_id]["overall_label"]
            in {"CONTRADICTED", "INSUFFICIENT"}
            and final[annotation_id]["materiality_decisive"] == "true"
        )
        for annotation_id in final
    }

    def estimates(
        claim_multiplicity: Counter[str] | None = None,
    ) -> dict[str, dict[str, float]]:
        multiplicity = claim_multiplicity or Counter({item: 1 for item in final})
        by_condition: dict[str, dict[str, float]] = {}
        for condition in conditions:
            by_base = {base_case_id: 0.0 for base_case_id in base_cases}
            for annotation_id, count in multiplicity.items():
                if not unsafe[annotation_id]:
                    continue
                for base_case_id, value in contributions[annotation_id][condition].items():
                    by_base[base_case_id] += count * value
            by_condition[condition] = by_base
        return by_condition

    point_by_condition = estimates()
    point = {
        condition: sum(point_by_condition[condition].values()) / len(base_cases)
        for condition in conditions
    }
    difference = point[intervention] - point[reference]

    by_stratum: dict[str, list[str]] = defaultdict(list)
    for key in keys:
        by_stratum[annotation_stratum(key)].append(key["annotation_id"])
    rng = random.Random(seed)
    bootstrap_differences: list[float] = []
    bootstrap_reference: list[float] = []
    bootstrap_intervention: list[float] = []
    for _ in range(resamples):
        claim_multiplicity = Counter(
            annotation_id
            for stratum in sorted(by_stratum)
            for annotation_id in rng.choices(
                by_stratum[stratum], k=len(by_stratum[stratum])
            )
        )
        sampled_by_condition = estimates(claim_multiplicity)
        sampled_base_cases = rng.choices(base_cases, k=len(base_cases))
        values = {
            condition: sum(
                sampled_by_condition[condition][base_case_id]
                for base_case_id in sampled_base_cases
            )
            / len(sampled_base_cases)
            for condition in conditions
        }
        bootstrap_reference.append(values[reference])
        bootstrap_intervention.append(values[intervention])
        bootstrap_differences.append(values[intervention] - values[reference])

    def interval(values: list[float]) -> list[float]:
        return [_quantile(values, 0.025), _quantile(values, 0.975)]

    return {
        "status": "adjudicated_design_weighted_estimate",
        "positive_definition": (
            "adjudicated overall label is CONTRADICTED or INSUFFICIENT and "
            "adjudicated materiality_decisive=true"
        ),
        "reference_condition": reference,
        "intervention_condition": intervention,
        "selected_claims": len(keys),
        "selected_claims_joined_to_primary_conditions": len(relevant_ids),
        "independent_base_cases": len(base_cases),
        "condition_estimates": {
            reference: {
                "surfaced_unwarranted_decisive_claims_per_base_case": point[reference],
                "confidence_interval": interval(bootstrap_reference),
            },
            intervention: {
                "surfaced_unwarranted_decisive_claims_per_base_case": point[intervention],
                "confidence_interval": interval(bootstrap_intervention),
            },
        },
        "contrast_intervention_minus_reference": {
            "estimate": difference,
            "confidence_interval": interval(bootstrap_differences),
        },
        "bootstrap": {
            "confidence_level": 0.95,
            "resamples": resamples,
            "seed": seed,
            "method": (
                "two-stage percentile bootstrap: claims resampled with replacement "
                "within annotation strata and base_case_id clusters resampled with "
                "replacement; inverse sampling-fraction weights retained"
            ),
        },
        "estimand_note": (
            "Human labels replace the mechanical warrant label for sampled claims; "
            "condition-specific delivery is joined from the frozen shared-response "
            "records. This is a sampling-weighted estimate, not a census."
        ),
    }


def _mechanical_annotations(
    keys: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> dict[str, dict[str, str]]:
    record_index: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        response_hash = record.get("generator_response_sha256")
        warrant = record.get("mechanical_warrant")
        if response_hash and warrant:
            record_index.setdefault((record["case_id"], response_hash), record)
    output: dict[str, dict[str, str]] = {}
    for key in keys:
        record_key = (key["case_id"], key["generator_response_sha256"])
        if record_key not in record_index:
            raise ValueError(f"mechanical warrant missing for {key['annotation_id']}")
        record = record_index[record_key]
        assessments = {
            assessment["claim_id"]: assessment
            for assessment in record["mechanical_warrant"]["assessments"]
        }
        if key["claim_id"] not in assessments:
            raise ValueError(f"mechanical claim missing for {key['annotation_id']}")
        assessment = assessments[key["claim_id"]]
        axes = {axis["axis"]: axis["label"] for axis in assessment["axes"]}
        output[key["annotation_id"]] = {
            "overall_label": assessment["overall_label"],
            "materiality_decisive": str(
                bool(assessment.get("decisive", key["generator_decisive"]))
            ).lower(),
            **{f"axis_{axis}": axes[axis] for axis in ANNOTATION_AXES},
        }
    return output


def analyze_human_annotations(
    package_dir: Path,
    records_path: Path,
    annotator_1_path: Path,
    annotator_2_path: Path,
    adjudication_path: Path,
) -> dict[str, Any]:
    """Validate a completed three-reviewer workflow and calculate audit metrics."""

    manifest_path = package_dir / "manifest.json"
    items_path = package_dir / "blind" / "items.jsonl"
    guide_path = package_dir / "blind" / "ANNOTATION_GUIDE.md"
    key_path = package_dir / "admin_do_not_share_with_annotators" / "key.jsonl"
    manifest = json.loads(manifest_path.read_text())
    if _sha256_bytes(items_path.read_bytes()) != manifest["items_sha256"]:
        raise ValueError("blind item hash does not match annotation manifest")
    if _sha256_bytes(guide_path.read_bytes()) != manifest["annotation_guide_sha256"]:
        raise ValueError("annotation guide hash does not match annotation manifest")
    if _sha256_bytes(key_path.read_bytes()) != manifest["admin_key_sha256"]:
        raise ValueError("administrative key hash does not match annotation manifest")
    keys = _read_jsonl(key_path)
    expected_ids = {item["annotation_id"] for item in keys}
    if len(expected_ids) != len(keys) or len(keys) != manifest["selected_claims"]:
        raise ValueError("annotation package contains duplicate or missing keys")

    population = manifest["population_stratum_counts"]
    selected = manifest["stratum_counts"]
    design_weights = {}
    observed_selected = Counter(annotation_stratum(item) for item in keys)
    if dict(sorted(observed_selected.items())) != selected:
        raise ValueError("selected stratum counts do not match annotation manifest")
    for item in keys:
        stratum = annotation_stratum(item)
        if not selected.get(stratum) or not population.get(stratum):
            raise ValueError(f"invalid sampling stratum {stratum}")
        design_weights[item["annotation_id"]] = population[stratum] / selected[stratum]

    first, first_id = load_complete_annotations(annotator_1_path, expected_ids)
    second, second_id = load_complete_annotations(annotator_2_path, expected_ids)
    final, adjudicator_id = load_complete_annotations(adjudication_path, expected_ids)
    if len({first_id, second_id, adjudicator_id}) != 3:
        raise ValueError("independent annotators and adjudicator need distinct IDs")

    inter_rater = {
        "overall": _agreement(first, second, "overall_label", design_weights),
        "materiality_decisive": _agreement(
            first, second, "materiality_decisive", design_weights
        ),
        "axes": {
            axis: _agreement(first, second, f"axis_{axis}", design_weights)
            for axis in ANNOTATION_AXES
        },
    }
    records = _read_jsonl(records_path)
    mechanical = _mechanical_annotations(keys, records)
    mechanical_validation = {
        "overall": {
            **_agreement(final, mechanical, "overall_label", design_weights),
            "confusion": _confusion(
                final, mechanical, "overall_label", design_weights
            ),
        },
        "materiality_decisive": {
            **_agreement(
                final, mechanical, "materiality_decisive", design_weights
            ),
            "confusion": _confusion(
                final, mechanical, "materiality_decisive", design_weights
            ),
        },
        "axes": {
            axis: {
                **_agreement(final, mechanical, f"axis_{axis}", design_weights),
                "confusion": _confusion(
                    final, mechanical, f"axis_{axis}", design_weights
                ),
            }
            for axis in ANNOTATION_AXES
        },
        "materially_unwarranted_flag": _binary_warrant_metrics(
            final, mechanical, design_weights
        ),
    }
    bootstrap = _bootstrap_human_metrics(
        keys, first, second, final, mechanical, design_weights
    )
    human_primary = _human_primary_endpoint(
        keys, final, records, design_weights
    )
    return {
        "human_analysis_version": HUMAN_ANALYSIS_VERSION,
        "annotation_export_version": manifest["annotation_export_version"],
        "sample": {
            "selected_claims": len(keys),
            "population_claims": sum(population.values()),
            "sampling_design": manifest["sampling_policy"],
            "design_weighted": True,
        },
        "reviewer_identity_policy": "opaque IDs hashed in analysis output",
        "reviewer_id_sha256": {
            "annotator_1": hashlib.sha256(first_id.encode()).hexdigest(),
            "annotator_2": hashlib.sha256(second_id.encode()).hexdigest(),
            "adjudicator": hashlib.sha256(adjudicator_id.encode()).hexdigest(),
        },
        "annotation_timing": {
            "measurement": (
                "offline interface active-visible time per item; no wall-clock "
                "timestamps or network telemetry"
            ),
            "annotator_1": _timing_summary(first),
            "annotator_2": _timing_summary(second),
            "adjudicator": _timing_summary(final),
        },
        "source_sha256": {
            "annotation_manifest": _sha256_bytes(manifest_path.read_bytes()),
            "annotation_guide": _sha256_bytes(guide_path.read_bytes()),
            "annotator_1": _sha256_bytes(annotator_1_path.read_bytes()),
            "annotator_2": _sha256_bytes(annotator_2_path.read_bytes()),
            "adjudication": _sha256_bytes(adjudication_path.read_bytes()),
            "records": _sha256_bytes(records_path.read_bytes()),
        },
        "inter_rater": inter_rater,
        "mechanical_validation": mechanical_validation,
        "human_primary_endpoint": human_primary,
        "bootstrap": bootstrap,
    }
