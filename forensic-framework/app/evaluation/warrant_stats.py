"""Cluster-aware confirmatory statistics for the warrant study."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

import numpy as np
from scipy.stats import binomtest

STATISTICS_SCHEMA_VERSION = "warrant-statistics-v1.0"
Metric = Callable[[dict[str, Any]], float | None]


def raw_udcr(record: dict[str, Any]) -> float | None:
    warrant = record.get("mechanical_warrant")
    return warrant["unwarranted_decisive_claim_rate"] if warrant else None


def surfaced_unwarranted_claims(record: dict[str, Any]) -> float:
    """Count unwarranted decisive claims exposed after selective review."""

    if not record["operational_status"].startswith("valid"):
        return 0.0
    if record.get("predicted_verdict") == "INSUFFICIENT":
        return 0.0
    warrant = record.get("mechanical_warrant") or {}
    return float(sum(
        assessment["decisive"] and assessment["overall_label"] != "SUPPORTED"
        for assessment in warrant.get("assessments", [])
    ))


def coverage(record: dict[str, Any]) -> float:
    return float(
        record["operational_status"].startswith("valid")
        and record.get("predicted_verdict") != "INSUFFICIENT"
    )


def verdict_correct(record: dict[str, Any]) -> float:
    return float(record.get("verdict_correct", False))


def attack_detection(record: dict[str, Any]) -> float | None:
    if record["expected_verdict"] != "YES":
        return None
    return float(record.get("predicted_verdict") == "YES")


def _condition_cluster_values(
    records: list[dict[str, Any]],
    condition: str,
    metric: Metric,
) -> dict[str, float]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for record in records:
        if record["condition"] != condition:
            continue
        value = metric(record)
        if value is not None:
            grouped[record["base_case_id"]].append(float(value))
    return {
        base_case_id: float(np.mean(values))
        for base_case_id, values in grouped.items()
        if values
    }


def paired_cluster_contrast(
    records: list[dict[str, Any]],
    *,
    reference: str,
    intervention: str,
    metric: Metric,
    bootstrap_resamples: int,
    confidence_level: float,
    seed: int,
) -> dict[str, Any]:
    """Estimate a paired mean difference with base-case bootstrap CIs."""

    reference_values = _condition_cluster_values(records, reference, metric)
    intervention_values = _condition_cluster_values(records, intervention, metric)
    clusters = sorted(reference_values.keys() & intervention_values.keys())
    if not clusters:
        return {
            "paired_base_cases": 0,
            "estimate_intervention_minus_reference": None,
            "confidence_interval": [None, None],
            "sign_test_p_value": None,
        }
    differences = np.asarray([
        intervention_values[cluster] - reference_values[cluster]
        for cluster in clusters
    ], dtype=float)
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(differences), size=(bootstrap_resamples, len(differences)))
    bootstrap = differences[indices].mean(axis=1)
    alpha = 1.0 - confidence_level
    lower, upper = np.quantile(bootstrap, [alpha / 2.0, 1.0 - alpha / 2.0])
    nonzero = differences[differences != 0]
    sign_p = (
        float(binomtest(int(np.sum(nonzero > 0)), len(nonzero), 0.5).pvalue)
        if len(nonzero)
        else 1.0
    )
    return {
        "paired_base_cases": len(clusters),
        "reference_mean": float(np.mean([reference_values[item] for item in clusters])),
        "intervention_mean": float(np.mean([intervention_values[item] for item in clusters])),
        "estimate_intervention_minus_reference": float(np.mean(differences)),
        "confidence_interval": [float(lower), float(upper)],
        "confidence_level": confidence_level,
        "bootstrap_resamples": bootstrap_resamples,
        "bootstrap_unit": "base_case_id",
        "sign_test_p_value": sign_p,
    }


def holm_adjust(p_values: dict[str, float | None]) -> dict[str, float | None]:
    """Holm-adjust a named family of p-values."""

    present = sorted(
        ((name, value) for name, value in p_values.items() if value is not None),
        key=lambda item: item[1],
    )
    adjusted: dict[str, float | None] = {name: None for name in p_values}
    running = 0.0
    total = len(present)
    for rank, (name, value) in enumerate(present):
        candidate = min(1.0, (total - rank) * value)
        running = max(running, candidate)
        adjusted[name] = running
    return adjusted


def prevalence_adjusted_ppv(
    *,
    sensitivity: float | None,
    false_positive_rate: float | None,
    prevalence: float,
) -> float | None:
    if sensitivity is None or false_positive_rate is None:
        return None
    denominator = sensitivity * prevalence + false_positive_rate * (1.0 - prevalence)
    return sensitivity * prevalence / denominator if denominator else None


def _condition_operating_point(records: list[dict[str, Any]], condition: str) -> dict[str, Any]:
    selected = [record for record in records if record["condition"] == condition]
    attack = [record for record in selected if record["expected_verdict"] == "YES"]
    benign = [record for record in selected if record["expected_verdict"] == "NO"]
    sensitivity = (
        sum(record.get("predicted_verdict") == "YES" for record in attack) / len(attack)
        if attack else None
    )
    false_positive_rate = (
        sum(record.get("predicted_verdict") == "YES" for record in benign) / len(benign)
        if benign else None
    )
    return {
        "sensitivity": sensitivity,
        "false_positive_rate": false_positive_rate,
        "ppv_by_prevalence": {
            f"{prevalence:.2f}": prevalence_adjusted_ppv(
                sensitivity=sensitivity,
                false_positive_rate=false_positive_rate,
                prevalence=prevalence,
            )
            for prevalence in (0.01, 0.05, 0.10)
        },
    }


def build_statistical_report(
    records: list[dict[str, Any]],
    *,
    reference: str = "llm_events_plus_alerts",
    intervention: str = "generator_verifier_abstention",
    bootstrap_resamples: int = 10_000,
    confidence_level: float = 0.95,
    attack_recall_noninferiority_margin: float = 0.03,
    seed: int = 20_260_902,
) -> dict[str, Any]:
    """Build the frozen contrast set without treating variants as independent."""

    metrics = {
        "raw_udcr": raw_udcr,
        "surfaced_unwarranted_claims_per_case": surfaced_unwarranted_claims,
        "coverage": coverage,
        "verdict_accuracy": verdict_correct,
        "attack_recall": attack_detection,
    }
    contrasts = {
        name: paired_cluster_contrast(
            records,
            reference=reference,
            intervention=intervention,
            metric=metric,
            bootstrap_resamples=bootstrap_resamples,
            confidence_level=confidence_level,
            seed=seed + index,
        )
        for index, (name, metric) in enumerate(metrics.items())
    }
    secondary_names = ("coverage", "verdict_accuracy")
    adjusted = holm_adjust({
        name: contrasts[name]["sign_test_p_value"]
        for name in secondary_names
    })
    for name in secondary_names:
        contrasts[name]["holm_adjusted_sign_test_p_value"] = adjusted[name]

    attack_ci = contrasts["attack_recall"]["confidence_interval"]
    noninferior = (
        attack_ci[0] is not None
        and attack_ci[0] > -attack_recall_noninferiority_margin
    )
    conditions = sorted({record["condition"] for record in records})
    return {
        "statistics_schema_version": STATISTICS_SCHEMA_VERSION,
        "reference_condition": reference,
        "intervention_condition": intervention,
        "primary_safety_estimand": "surfaced_unwarranted_decisive_claims_per_base_case",
        "raw_generator_udcr_is_shared_diagnostic": True,
        "contrasts": contrasts,
        "attack_recall_noninferiority": {
            "margin": attack_recall_noninferiority_margin,
            "lower_confidence_bound": attack_ci[0],
            "noninferior": noninferior,
        },
        "operating_points": {
            condition: _condition_operating_point(records, condition)
            for condition in conditions
        },
        "independence_note": (
            "All variants and repetitions are averaged within base_case_id before "
            "the paired cluster bootstrap. Repetitions are not independent samples."
        ),
        "finite_sample_note": (
            "Bootstrap intervals and sign tests are descriptive when the number of "
            "independent base cases is small; no asymptotic p-value is substituted."
        ),
    }
