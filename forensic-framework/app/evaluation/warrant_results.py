"""Reproducible scoring and integrity checks for warrant LLM runs."""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.ingestion.warrant_benchmark import PROJECT_ROOT

RESULTS_SCHEMA_VERSION = "warrant-results-v1.1"
CONFIDENCE_AUDIT_SCHEMA_VERSION = "warrant-confidence-audit-v1.0"
CONFIDENCE_AUDIT_THRESHOLDS = (
    0.0,
    0.65,
    0.70,
    0.75,
    0.80,
    0.85,
    0.90,
    0.95,
    1.0,
)


def load_run_records(path: Path) -> list[dict[str, Any]]:
    """Load one append-only JSONL run and reject duplicate run keys."""

    records = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    keys = [
        (record["case_id"], record["condition"], record["repetition"])
        for record in records
    ]
    if len(keys) != len(set(keys)):
        raise ValueError(f"duplicate case-condition-repetition record in {path}")
    return records


def _safe_rate(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def _mean(values: list[float]) -> float | None:
    return statistics.mean(values) if values else None


def _percentile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = round((len(ordered) - 1) * probability)
    return ordered[index]


def _claim_counts(record: dict[str, Any]) -> tuple[int, int]:
    warrant = record.get("mechanical_warrant")
    if not warrant:
        return 0, 0
    decisive = int(warrant["decisive_claims"])
    unwarranted = sum(
        assessment["decisive"] and assessment["overall_label"] != "SUPPORTED"
        for assessment in warrant["assessments"]
    )
    return decisive, unwarranted


def _generator_confidence(record: dict[str, Any]) -> float:
    parsed = ((record.get("generator") or {}).get("parsed_output") or {})
    value = parsed.get("overall_confidence")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            "valid alert-visible output lacks numeric generator overall_confidence: "
            f"{record.get('case_id')} repetition {record.get('repetition')}"
        )
    confidence = float(value)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(
            f"generator overall_confidence outside [0, 1]: {confidence}"
        )
    return confidence


def _calibration_summary(
    confidences: list[float],
    outcomes: list[float],
) -> dict[str, Any]:
    """Return fixed-bin descriptive calibration metrics.

    Outputs may be correlated within base case, so these values are diagnostics,
    not inferential estimates.  Fixed-width bins avoid outcome-aware binning.
    """

    if len(confidences) != len(outcomes) or not confidences:
        raise ValueError("calibration inputs must be non-empty and equal length")
    bins: list[dict[str, Any]] = []
    weighted_error = 0.0
    maximum_error = 0.0
    for index in range(10):
        members = [
            position
            for position, confidence in enumerate(confidences)
            if min(int(confidence * 10), 9) == index
        ]
        if not members:
            continue
        mean_confidence = statistics.mean(
            confidences[position] for position in members
        )
        outcome_rate = statistics.mean(outcomes[position] for position in members)
        absolute_gap = abs(mean_confidence - outcome_rate)
        weighted_error += len(members) / len(confidences) * absolute_gap
        maximum_error = max(maximum_error, absolute_gap)
        bins.append({
            "lower": index / 10,
            "upper": (index + 1) / 10,
            "upper_inclusive": index == 9,
            "n": len(members),
            "mean_confidence": mean_confidence,
            "outcome_rate": outcome_rate,
            "absolute_gap": absolute_gap,
        })
    mean_confidence = statistics.mean(confidences)
    outcome_rate = statistics.mean(outcomes)
    return {
        "n": len(confidences),
        "mean_reported_confidence": mean_confidence,
        "positive_outcome_rate": outcome_rate,
        "mean_confidence_minus_outcome_rate": mean_confidence - outcome_rate,
        "brier_score": statistics.mean(
            (confidence - outcome) ** 2
            for confidence, outcome in zip(confidences, outcomes)
        ),
        "ece_10_equal_width": weighted_error,
        "maximum_calibration_error": maximum_error,
        "nonempty_bin_count": len(bins),
        "bins": bins,
    }


def confidence_diagnostics(
    records: list[dict[str, Any]],
    *,
    condition: str = "llm_events_plus_alerts",
    policy_threshold: float = 0.65,
) -> dict[str, Any]:
    """Audit generator confidence without selecting a threshold.

    The policy consumes generator confidence from the shared alert-visible
    generation.  Invalid generations remain in the operational denominator but
    cannot contribute a confidence value.
    """

    selected = [
        record for record in records if record.get("condition") == condition
    ]
    if not selected:
        raise ValueError(f"run has no records for confidence condition {condition}")
    valid = [
        record
        for record in selected
        if str(record.get("operational_status", "")).startswith("valid")
    ]
    if not valid:
        raise ValueError(f"condition {condition} has no valid outputs")
    confidences = [_generator_confidence(record) for record in valid]
    verdict_outcomes = [float(bool(record.get("verdict_correct"))) for record in valid]
    exact_outcomes = [float(bool(record.get("exact_correct"))) for record in valid]
    unsafe_counts = [_claim_counts(record)[1] for record in valid]
    if any(record.get("mechanical_warrant") is None for record in valid):
        raise ValueError("valid confidence-audit record lacks mechanical warrant data")
    mechanically_safe = [float(count == 0) for count in unsafe_counts]

    frequency: dict[float, int] = defaultdict(int)
    for confidence in confidences:
        frequency[confidence] += 1

    risk_coverage = []
    for threshold in CONFIDENCE_AUDIT_THRESHOLDS:
        accepted_positions = [
            index
            for index, confidence in enumerate(confidences)
            if confidence >= threshold
        ]
        accepted_n = len(accepted_positions)
        risk_coverage.append({
            "threshold": threshold,
            "selected_valid_n": accepted_n,
            "rejected_valid_n": len(valid) - accepted_n,
            "valid_output_coverage": _safe_rate(accepted_n, len(valid)),
            "operational_coverage": _safe_rate(accepted_n, len(selected)),
            "verdict_selective_risk": (
                1.0
                - statistics.mean(verdict_outcomes[index] for index in accepted_positions)
                if accepted_positions
                else None
            ),
            "exact_selective_risk": (
                1.0
                - statistics.mean(exact_outcomes[index] for index in accepted_positions)
                if accepted_positions
                else None
            ),
            "mechanically_unsafe_record_rate": (
                1.0
                - statistics.mean(mechanically_safe[index] for index in accepted_positions)
                if accepted_positions
                else None
            ),
            "mean_unwarranted_decisive_claims": (
                statistics.mean(unsafe_counts[index] for index in accepted_positions)
                if accepted_positions
                else None
            ),
        })

    rejected_by_policy = sum(
        confidence < policy_threshold for confidence in confidences
    )
    return {
        "condition": condition,
        "record_n": len(selected),
        "valid_output_n": len(valid),
        "operational_failure_n": len(selected) - len(valid),
        "base_case_n": len({record["base_case_id"] for record in selected}),
        "confidence_source": "generator.parsed_output.overall_confidence",
        "confidence_target_semantics": (
            "The frozen schema bounds an overall score to [0,1] but does not "
            "define whether it predicts verdict correctness, exact verdict-plus-"
            "suspect correctness, or claim-level warrant."
        ),
        "minimum_confidence": min(confidences),
        "maximum_confidence": max(confidences),
        "mean_confidence": statistics.mean(confidences),
        "distinct_confidence_values": len(frequency),
        "singleton_confidence_values": sum(
            count == 1 for count in frequency.values()
        ),
        "confidence_frequency": [
            {"confidence": confidence, "n": count}
            for confidence, count in sorted(frequency.items())
        ],
        "frozen_threshold_rule": {
            "threshold": policy_threshold,
            "comparison": "reject when confidence < threshold",
            "rejected_valid_n": rejected_by_policy,
            "rejected_valid_rate": _safe_rate(rejected_by_policy, len(valid)),
            "status": (
                "inert_on_valid_outputs"
                if rejected_by_policy == 0
                else "active_on_valid_outputs"
            ),
        },
        "calibration": {
            "verdict_correct": {
                "positive_outcome_definition": "three-way verdict is correct",
                **_calibration_summary(confidences, verdict_outcomes),
            },
            "exact_correct": {
                "positive_outcome_definition": (
                    "both verdict and required suspect attribution are correct"
                ),
                **_calibration_summary(confidences, exact_outcomes),
            },
            "mechanically_zero_unsafe_claims": {
                "positive_outcome_definition": (
                    "record contains zero mechanically unwarranted decisive claims"
                ),
                **_calibration_summary(confidences, mechanically_safe),
            },
        },
        "risk_coverage": risk_coverage,
        "interpretation_boundary": (
            "Per-output calibration and threshold rows are retrospective, "
            "descriptive diagnostics. Variants and repetitions are nested within "
            "base cases and are not treated as independent inferential units."
        ),
    }


def build_confidence_audit(
    development_records: list[dict[str, Any]],
    test_records: list[dict[str, Any]],
    *,
    development_records_sha256: str,
    test_records_sha256: str,
    condition: str = "llm_events_plus_alerts",
    policy_threshold: float = 0.65,
) -> dict[str, Any]:
    """Build a deterministic, source-bound confidence-policy audit."""

    if not 0.0 <= policy_threshold <= 1.0:
        raise ValueError("policy threshold must be in [0, 1]")
    development_splits = {record.get("split") for record in development_records}
    test_splits = {record.get("split") for record in test_records}
    if development_splits != {"development"}:
        raise ValueError(f"expected development-only records, found {development_splits}")
    if test_splits != {"test"}:
        raise ValueError(f"expected test-only records, found {test_splits}")
    development_ids = {record["base_case_id"] for record in development_records}
    test_ids = {record["base_case_id"] for record in test_records}
    overlap = sorted(development_ids & test_ids)
    if overlap:
        raise ValueError(f"development/test base-case overlap: {overlap[:5]}")
    development_run_ids = {record["run_id"] for record in development_records}
    test_run_ids = {record["run_id"] for record in test_records}
    if len(development_run_ids) != 1 or len(test_run_ids) != 1:
        raise ValueError("confidence audit requires exactly one development and one test run")

    development = confidence_diagnostics(
        development_records,
        condition=condition,
        policy_threshold=policy_threshold,
    )
    test = confidence_diagnostics(
        test_records,
        condition=condition,
        policy_threshold=policy_threshold,
    )
    return {
        "confidence_audit_schema_version": CONFIDENCE_AUDIT_SCHEMA_VERSION,
        "analysis_role": "post-hoc calibration and abstention diagnostic",
        "source_sha256": {
            "development_records": development_records_sha256,
            "test_records": test_records_sha256,
        },
        "source_run_ids": {
            "development": sorted(development_run_ids),
            "test": sorted(test_run_ids),
        },
        "split_integrity": {
            "development_base_case_n": len(development_ids),
            "test_base_case_n": len(test_ids),
            "overlap_n": 0,
        },
        "development": development,
        "test": test,
        "calibrator_fit_decision": {
            "status": "not_fit",
            "threshold_selected": None,
            "reasons": [
                (
                    f"The development partition has only {development['base_case_n']} "
                    "independent base cases."
                ),
                (
                    "Development confidence has only "
                    f"{development['distinct_confidence_values']} distinct values, "
                    f"including {development['singleton_confidence_values']} "
                    "singleton levels."
                ),
                (
                    f"The frozen {policy_threshold:.2f} confidence gate rejected "
                    f"{development['frozen_threshold_rule']['rejected_valid_n']} valid "
                    "development outputs, so its local rejection behavior is unobserved."
                ),
                "The frozen prompt and schema do not define the score's prediction target.",
            ],
        },
        "held_out_use_boundary": (
            "Test labels were used only for this retrospective diagnostic. No "
            "calibrator or replacement threshold was selected, and H5 remains untested."
        ),
    }


def _causal_error(record: dict[str, Any]) -> bool:
    warrant = record.get("mechanical_warrant") or {}
    return any(
        assessment["decisive"]
        and any(
            axis["axis"] == "causality"
            and axis["label"] in {"CONTRADICTED", "INSUFFICIENT"}
            for axis in assessment["axes"]
        )
        for assessment in warrant.get("assessments", [])
    )


def summarize_condition(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize one model-condition sample with failures retained."""

    total = len(records)
    valid = [record for record in records if record["operational_status"].startswith("valid")]
    delivered = [record for record in valid if record["predicted_verdict"] != "INSUFFICIENT"]
    attack = [record for record in records if record["expected_verdict"] == "YES"]
    benign = [record for record in records if record["expected_verdict"] == "NO"]

    decisive = unwarranted = 0
    delivered_decisive = delivered_unwarranted = 0
    for record in valid:
        case_decisive, case_unwarranted = _claim_counts(record)
        decisive += case_decisive
        unwarranted += case_unwarranted
        if record in delivered:
            delivered_decisive += case_decisive
            delivered_unwarranted += case_unwarranted

    citation_validity = [
        record["mechanical_warrant"]["citation_validity"]
        for record in valid
        if record.get("mechanical_warrant")
    ]
    citation_completeness = [
        record["mechanical_warrant"]["citation_completeness"]
        for record in valid
        if record.get("mechanical_warrant")
    ]
    counter_recall = [
        record["mechanical_counterevidence"]["recall"]
        for record in valid
        if record.get("mechanical_counterevidence")
        and record["mechanical_counterevidence"]["recall"] is not None
    ]
    raw_udcr = [
        record["mechanical_warrant"]["unwarranted_decisive_claim_rate"]
        for record in valid
        if record.get("mechanical_warrant")
    ]
    self_or_verifier_abstentions = sum(
        ((record.get("verifier") or {}).get("parsed_output") or {}).get(
            "recommended_verdict"
        ) == "INSUFFICIENT"
        for record in records
    )

    return {
        "n": total,
        "valid_n": len(valid),
        "operational_failure_rate": _safe_rate(total - len(valid), total),
        "generator_failure_rate": _safe_rate(
            sum(record["operational_status"] == "generator_failure" for record in records),
            total,
        ),
        "review_failure_rate": _safe_rate(
            sum(record["operational_status"] == "review_failure" for record in records),
            total,
        ),
        "verdict_accuracy": _safe_rate(sum(record.get("verdict_correct", False) for record in records), total),
        "verdict_and_suspect_exact_accuracy": _safe_rate(
            sum(record.get("exact_correct", False) for record in records), total
        ),
        "attack_recall": _safe_rate(
            sum(record.get("predicted_verdict") == "YES" for record in attack),
            len(attack),
        ),
        "benign_rejection": _safe_rate(
            sum(record.get("predicted_verdict") == "NO" for record in benign),
            len(benign),
        ),
        "abstention_rate": _safe_rate(
            sum(record.get("predicted_verdict") == "INSUFFICIENT" for record in records),
            total,
        ),
        "coverage": _safe_rate(len(delivered), total),
        "selective_exact_accuracy": _safe_rate(
            sum(record.get("exact_correct", False) for record in delivered),
            len(delivered),
        ),
        "raw_udcr_macro": _mean(raw_udcr),
        "raw_udcr_micro": _safe_rate(unwarranted, decisive),
        "delivered_udcr_micro": _safe_rate(delivered_unwarranted, delivered_decisive),
        "surfaced_unwarranted_decisive_claims_per_case": _safe_rate(
            delivered_unwarranted, total
        ),
        "zero_raw_udcr_rate": _safe_rate(sum(value == 0 for value in raw_udcr), len(raw_udcr)),
        "citation_validity": _mean(citation_validity),
        "citation_completeness": _mean(citation_completeness),
        "counterevidence_recall": _mean(counter_recall),
        "decisive_causal_error_rate": _safe_rate(sum(map(_causal_error, valid)), len(valid)),
        "mechanical_allow_rate": _safe_rate(
            sum(
                (record.get("mechanical_review") or {}).get("disposition") == "ALLOW"
                for record in records
            ),
            total,
        ),
        "review_recommended_abstention_rate": _safe_rate(
            self_or_verifier_abstentions, total
        ),
        "decisive_claims": decisive,
        "unwarranted_decisive_claims": unwarranted,
        "delivered_decisive_claims": delivered_decisive,
        "delivered_unwarranted_decisive_claims": delivered_unwarranted,
    }


def paired_effects(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute within-generation and alert-context diagnostic contrasts."""

    index = {
        (record["case_id"], record["condition"], record["repetition"]): record
        for record in records
    }
    case_repetitions = sorted({
        (record["case_id"], record["repetition"])
        for record in records
    })
    alert_pairs = []
    review_pairs = []
    for case_id, repetition in case_repetitions:
        events = index.get((case_id, "llm_events_only", repetition))
        alerts = index.get((case_id, "llm_events_plus_alerts", repetition))
        if events and alerts and events.get("mechanical_warrant") and alerts.get("mechanical_warrant"):
            alert_pairs.append((events, alerts))
        base = alerts
        for condition in (
            "llm_self_review",
            "generator_verifier",
            "generator_verifier_abstention",
        ):
            reviewed = index.get((case_id, condition, repetition))
            if base and reviewed:
                review_pairs.append((condition, base, reviewed))

    by_review: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for condition, base, reviewed in review_pairs:
        by_review[condition].append((base, reviewed))

    return {
        "events_only_vs_alerts": {
            "paired_n": len(alert_pairs),
            "verdict_flip_rate": _safe_rate(
                sum(left["predicted_verdict"] != right["predicted_verdict"] for left, right in alert_pairs),
                len(alert_pairs),
            ),
            "suspect_flip_rate": _safe_rate(
                sum(left["predicted_suspect"] != right["predicted_suspect"] for left, right in alert_pairs),
                len(alert_pairs),
            ),
            "mean_udcr_change_alerts_minus_events": _mean([
                right["mechanical_warrant"]["unwarranted_decisive_claim_rate"]
                - left["mechanical_warrant"]["unwarranted_decisive_claim_rate"]
                for left, right in alert_pairs
            ]),
            "alert_increased_udcr_rate": _safe_rate(
                sum(
                    right["mechanical_warrant"]["unwarranted_decisive_claim_rate"]
                    > left["mechanical_warrant"]["unwarranted_decisive_claim_rate"]
                    for left, right in alert_pairs
                ),
                len(alert_pairs),
            ),
            "new_decisive_causal_error_rate": _safe_rate(
                sum(not _causal_error(left) and _causal_error(right) for left, right in alert_pairs),
                len(alert_pairs),
            ),
        },
        "shared_generation_reviews": {
            condition: {
                "paired_n": len(pairs),
                "generator_hash_match_rate": _safe_rate(
                    sum(
                        base.get("generator_response_sha256")
                        == reviewed.get("generator_response_sha256")
                        for base, reviewed in pairs
                    ),
                    len(pairs),
                ),
                "new_abstention_rate": _safe_rate(
                    sum(
                        base["predicted_verdict"] != "INSUFFICIENT"
                        and reviewed["predicted_verdict"] == "INSUFFICIENT"
                        for base, reviewed in pairs
                    ),
                    len(pairs),
                ),
            }
            for condition, pairs in sorted(by_review.items())
        },
    }


def _delivered_value(record: dict[str, Any]) -> float:
    return float(
        record["operational_status"].startswith("valid")
        and record.get("predicted_verdict") != "INSUFFICIENT"
    )


def _surfaced_unsafe_value(record: dict[str, Any]) -> float:
    if not _delivered_value(record):
        return 0.0
    return float(_claim_counts(record)[1])


def _base_case_macro(
    values: list[tuple[str, float]],
) -> float | None:
    grouped: dict[str, list[float]] = defaultdict(list)
    for base_case_id, value in values:
        grouped[base_case_id].append(value)
    return _mean([_mean(items) for items in grouped.values() if items])


def variant_contrasts(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare each mutation with its canonical record within base case.

    These are descriptive, base-case-macro contrasts.  They do not replace the
    pre-specified primary intervention contrast or make repetitions independent.
    """

    index = {
        (
            record["base_case_id"],
            record["variant"],
            record["condition"],
            record["repetition"],
        ): record
        for record in records
    }
    variants = sorted({record["variant"] for record in records} - {"canonical"})
    conditions = sorted({record["condition"] for record in records})
    result: dict[str, Any] = {}
    for variant in variants:
        by_condition: dict[str, Any] = {}
        for condition in conditions:
            pairs = []
            for key, mutated in index.items():
                base_case_id, key_variant, key_condition, repetition = key
                if key_variant != variant or key_condition != condition:
                    continue
                canonical = index.get(
                    (base_case_id, "canonical", condition, repetition)
                )
                if canonical is not None:
                    pairs.append((base_case_id, canonical, mutated))
            if not pairs:
                continue

            expected_changes = [
                (base, float(left["expected_verdict"] != right["expected_verdict"]))
                for base, left, right in pairs
            ]
            changed_target_pairs = [
                (base, left, right)
                for base, left, right in pairs
                if left["expected_verdict"] != right["expected_verdict"]
            ]
            by_condition[condition] = {
                "paired_record_n": len(pairs),
                "base_case_n": len({base for base, _, _ in pairs}),
                "expected_verdict_change_rate": _base_case_macro(expected_changes),
                "verdict_flip_rate": _base_case_macro([
                    (base, float(left.get("predicted_verdict") != right.get("predicted_verdict")))
                    for base, left, right in pairs
                ]),
                "suspect_flip_rate": _base_case_macro([
                    (base, float(left.get("predicted_suspect") != right.get("predicted_suspect")))
                    for base, left, right in pairs
                ]),
                "coverage_change_mutated_minus_canonical": _base_case_macro([
                    (base, _delivered_value(right) - _delivered_value(left))
                    for base, left, right in pairs
                ]),
                "unsafe_exposure_change_mutated_minus_canonical": _base_case_macro([
                    (
                        base,
                        _surfaced_unsafe_value(right) - _surfaced_unsafe_value(left),
                    )
                    for base, left, right in pairs
                ]),
                "exact_accuracy_change_mutated_minus_canonical": _base_case_macro([
                    (
                        base,
                        float(right.get("exact_correct", False))
                        - float(left.get("exact_correct", False)),
                    )
                    for base, left, right in pairs
                ]),
                "correct_expected_transition_rate": _base_case_macro([
                    (
                        base,
                        float(
                            left.get("predicted_verdict") == left["expected_verdict"]
                            and right.get("predicted_verdict") == right["expected_verdict"]
                        ),
                    )
                    for base, left, right in changed_target_pairs
                ]),
            }
        result[variant] = by_condition
    return result


def axis_error_profile(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize mechanical axis labels without treating claims as independent."""

    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    decisive_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for record in records:
        warrant = record.get("mechanical_warrant") or {}
        for assessment in warrant.get("assessments", []):
            for axis in assessment.get("axes", []):
                counts[axis["axis"]][axis["label"]] += 1
                if assessment.get("decisive"):
                    decisive_counts[axis["axis"]][axis["label"]] += 1

    def summarize(source: dict[str, dict[str, int]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for axis, labels in sorted(source.items()):
            applicable = sum(
                count for label, count in labels.items()
                if label != "NOT_APPLICABLE"
            )
            unwarranted = sum(
                count for label, count in labels.items()
                if label in {"CONTRADICTED", "INSUFFICIENT"}
            )
            result[axis] = {
                "labels": dict(sorted(labels.items())),
                "applicable": applicable,
                "unwarranted": unwarranted,
                "unwarranted_rate": _safe_rate(unwarranted, applicable),
            }
        return result

    return {
        "all_claims": summarize(counts),
        "decisive_claims": summarize(decisive_counts),
        "interpretation_note": (
            "Counts are descriptive mechanical labels nested within base cases; "
            "they are not independent observations or expert error rates."
        ),
    }


def operation_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Deduplicate shared raw calls before reporting latency and token use."""

    calls: dict[str, tuple[str, dict[str, Any]]] = {}
    for record in records:
        for stage in ("generator", "verifier"):
            call = ((record.get(stage) or {}).get("call") or {})
            digest = call.get("raw_response_sha256")
            if not digest:
                continue
            if stage == "generator":
                role = "generator"
            elif record["condition"] == "llm_self_review":
                role = "self_review"
            else:
                role = "alert_blind_verifier"
            # Shared downstream records reuse the same raw artifact path.  Two
            # genuinely separate calls may return byte-identical JSON, so a
            # content digest alone would incorrectly collapse them.
            call_key = call.get("raw_response_path") or f"{role}:{digest}"
            calls.setdefault(call_key, (role, call))

    by_role: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for role, call in calls.values():
        by_role[role].append(call)

    def summarize(selected: list[dict[str, Any]]) -> dict[str, Any]:
        latencies = [float(call["latency_ms"]) for call in selected if call.get("latency_ms") is not None]
        input_tokens = [int(call["input_tokens"]) for call in selected if call.get("input_tokens") is not None]
        output_tokens = [int(call["output_tokens"]) for call in selected if call.get("output_tokens") is not None]
        costs = [float(call["estimated_cost_usd"]) for call in selected if call.get("estimated_cost_usd") is not None]
        return {
            "unique_calls": len(selected),
            "latency_ms_median": _percentile(latencies, 0.5),
            "latency_ms_p95": _percentile(latencies, 0.95),
            "input_tokens_total": sum(input_tokens),
            "output_tokens_total": sum(output_tokens),
            "estimated_cost_usd_total": sum(costs) if costs else None,
            "cost_coverage_rate": _safe_rate(len(costs), len(selected)),
        }

    return {
        "overall": summarize([call for _, call in calls.values()]),
        "by_role": {
            role: summarize(selected)
            for role, selected in sorted(by_role.items())
        },
        "deduplication_note": (
            "Calls shared across review-condition records are counted once by "
            "raw-response artifact path; byte-identical independent calls remain "
            "distinct."
        ),
    }


def _condition_summaries(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_condition: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_condition[record["condition"]].append(record)
    return {
        condition: summarize_condition(selected)
        for condition, selected in sorted(by_condition.items())
    }


def grouped_diagnostics(
    records: list[dict[str, Any]],
    field: str,
    *,
    include_paired_effects: bool,
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[str(record[field])].append(record)
    return {
        value: {
            "conditions": _condition_summaries(selected),
            **({"paired_effects": paired_effects(selected)} if include_paired_effects else {}),
        }
        for value, selected in sorted(grouped.items())
    }


def verify_artifacts(
    records: list[dict[str, Any]],
    *,
    allow_omitted_raw: bool = False,
) -> dict[str, Any]:
    """Verify retained raw bytes and pairing invariants.

    ``allow_omitted_raw`` is only for a release that deliberately excludes the
    entire raw-transcript layer.  A partial raw set is still an integrity error,
    and every retained file is always hash-checked.
    """

    checked: dict[str, str] = {}
    referenced: dict[str, str] = {}
    missing: set[str] = set()
    errors: list[str] = []
    for record in records:
        for stage in ("generator", "verifier"):
            metadata = record.get(stage) or {}
            call = metadata.get("call") or {}
            path_value = call.get("raw_response_path")
            expected = call.get("raw_response_sha256")
            if not path_value or not expected:
                continue
            path = Path(path_value)
            if not path.is_absolute():
                path = PROJECT_ROOT / path
            referenced[str(path)] = expected
            if not path.exists():
                missing.add(str(path))
                continue
            # Hash the retained bytes, not newline-normalized text. Provider
            # responses may legally contain CRLF inside string content.
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            if actual != expected:
                errors.append(f"raw response hash mismatch: {path_value}")
            checked[str(path)] = actual

    if missing:
        if allow_omitted_raw and not checked:
            raw_status = "omitted_by_release_policy"
        elif allow_omitted_raw:
            raw_status = "incomplete"
            errors.append(
                "partial raw-response set: release omission is permitted only "
                f"when all raw files are absent ({len(missing)} missing, "
                f"{len(checked)} retained)"
            )
        else:
            raw_status = "incomplete"
            errors.extend(
                f"missing raw response: {path}"
                for path in sorted(missing)
            )
    else:
        raw_status = "verified"

    grouped: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["condition"] in {
            "llm_events_plus_alerts",
            "llm_self_review",
            "generator_verifier",
            "generator_verifier_abstention",
        }:
            grouped[(record["case_id"], record["repetition"])].append(record)
    for key, group in grouped.items():
        hashes = {record.get("generator_response_sha256") for record in group}
        if len(hashes) != 1:
            errors.append(f"alert-visible generator pairing mismatch: {key}")
        verifier_group = [
            record for record in group
            if record["condition"] in {"generator_verifier", "generator_verifier_abstention"}
        ]
        verifier_hashes = {
            ((record.get("verifier") or {}).get("call") or {}).get("raw_response_sha256")
            for record in verifier_group
        }
        if len(verifier_group) > 1 and len(verifier_hashes) != 1:
            errors.append(f"verifier pairing mismatch: {key}")

    return {
        "ok": not errors,
        "raw_response_status": raw_status,
        "unique_raw_responses_referenced": len(referenced),
        "unique_raw_responses_checked": len(checked),
        "unique_raw_responses_missing": len(missing),
        "errors": errors,
    }


def summarize_run(
    records: list[dict[str, Any]],
    *,
    allow_omitted_raw: bool = False,
) -> dict[str, Any]:
    if not records:
        raise ValueError("cannot summarize an empty run")
    run_ids = {record["run_id"] for record in records}
    if len(run_ids) != 1:
        raise ValueError("records from multiple runs must be summarized separately")
    conditions = _condition_summaries(records)
    generator_conditions = {
        condition: axis_error_profile([
            record for record in records if record["condition"] == condition
        ])
        for condition in ("llm_events_only", "llm_events_plus_alerts")
        if condition in conditions
    }
    return {
        "results_schema_version": RESULTS_SCHEMA_VERSION,
        "run_id": next(iter(run_ids)),
        "requested_model": records[0]["requested_model"],
        "split": sorted({record["split"] for record in records}),
        "base_case_count": len({record["base_case_id"] for record in records}),
        "record_count": len(records),
        "conditions": conditions,
        "paired_effects": paired_effects(records),
        "variant_contrasts": variant_contrasts(records),
        "by_variant": grouped_diagnostics(
            records, "variant", include_paired_effects=True
        ),
        "by_family": grouped_diagnostics(
            records, "family", include_paired_effects=False
        ),
        "mechanical_axis_profiles": generator_conditions,
        "operations": operation_summary(records),
        "artifact_integrity": verify_artifacts(
            records,
            allow_omitted_raw=allow_omitted_raw,
        ),
    }
