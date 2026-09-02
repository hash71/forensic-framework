"""Reproducible scoring and integrity checks for warrant LLM runs."""

from __future__ import annotations

import hashlib
import json
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any

from app.ingestion.warrant_benchmark import PROJECT_ROOT

RESULTS_SCHEMA_VERSION = "warrant-results-v1.0"


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


def verify_artifacts(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Verify every retained raw-response hash and pairing invariant."""

    checked: dict[str, str] = {}
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
            if not path.exists():
                errors.append(f"missing raw response: {path_value}")
                continue
            actual = hashlib.sha256(path.read_text().encode()).hexdigest()
            if actual != expected:
                errors.append(f"raw response hash mismatch: {path_value}")
            checked[str(path)] = actual

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
        "unique_raw_responses_checked": len(checked),
        "errors": errors,
    }


def summarize_run(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not records:
        raise ValueError("cannot summarize an empty run")
    run_ids = {record["run_id"] for record in records}
    if len(run_ids) != 1:
        raise ValueError("records from multiple runs must be summarized separately")
    by_condition: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_condition[record["condition"]].append(record)
    return {
        "results_schema_version": RESULTS_SCHEMA_VERSION,
        "run_id": next(iter(run_ids)),
        "requested_model": records[0]["requested_model"],
        "split": sorted({record["split"] for record in records}),
        "base_case_count": len({record["base_case_id"] for record in records}),
        "record_count": len(records),
        "conditions": {
            condition: summarize_condition(condition_records)
            for condition, condition_records in sorted(by_condition.items())
        },
        "paired_effects": paired_effects(records),
        "artifact_integrity": verify_artifacts(records),
    }
