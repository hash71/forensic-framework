"""Tests for cluster-aware warrant statistics."""

from __future__ import annotations

from app.evaluation.warrant_stats import (
    build_statistical_report,
    holm_adjust,
    paired_cluster_contrast,
    prevalence_adjusted_ppv,
    verdict_correct,
)


def _record(base: str, condition: str, correct: bool, variant: str = "canonical") -> dict:
    return {
        "base_case_id": base,
        "case_id": f"{base}__{variant}",
        "variant": variant,
        "condition": condition,
        "repetition": 0,
        "expected_verdict": "YES" if base in {"b1", "b2"} else "NO",
        "predicted_verdict": ("YES" if base in {"b1", "b2"} else "NO") if correct else "INSUFFICIENT",
        "operational_status": "valid" if correct else "valid_abstained",
        "verdict_correct": correct,
        "mechanical_warrant": {
            "unwarranted_decisive_claim_rate": (
                0.5 if condition in {"reference", "llm_events_plus_alerts"} else 0.0
            ),
            "assessments": [
                {
                    "decisive": True,
                    "overall_label": (
                        "INSUFFICIENT"
                        if condition in {"reference", "llm_events_plus_alerts"}
                        else "SUPPORTED"
                    ),
                }
            ],
        },
    }


def test_cluster_contrast_averages_variants_within_base_case():
    records = []
    for base in ("b1", "b2"):
        for variant in ("canonical", "noise"):
            records.extend([
                _record(base, "reference", False, variant),
                _record(base, "intervention", True, variant),
            ])
    contrast = paired_cluster_contrast(
        records,
        reference="reference",
        intervention="intervention",
        metric=verdict_correct,
        bootstrap_resamples=100,
        confidence_level=0.95,
        seed=7,
    )

    assert contrast["paired_base_cases"] == 2
    assert contrast["estimate_intervention_minus_reference"] == 1.0
    assert contrast["confidence_interval"] == [1.0, 1.0]


def test_holm_adjustment_is_monotone_in_sorted_order():
    adjusted = holm_adjust({"a": 0.01, "b": 0.04, "c": 0.20, "missing": None})
    assert adjusted == {"a": 0.03, "b": 0.08, "c": 0.20, "missing": None}


def test_prevalence_adjustment_penalizes_false_positives_at_low_base_rate():
    ppv = prevalence_adjusted_ppv(
        sensitivity=0.95,
        false_positive_rate=0.05,
        prevalence=0.01,
    )
    assert ppv is not None
    assert 0.15 < ppv < 0.17


def test_report_applies_noninferiority_to_attack_clusters_only():
    records = []
    for base in ("b1", "b2", "b3"):
        records.extend([
            _record(base, "llm_events_plus_alerts", True),
            _record(base, "generator_verifier_abstention", True),
        ])
    report = build_statistical_report(records, bootstrap_resamples=100, seed=11)

    assert report["contrasts"]["attack_recall"]["paired_base_cases"] == 2
    assert report["attack_recall_noninferiority"]["noninferior"] is True
    assert report["contrasts"]["raw_udcr"]["estimate_intervention_minus_reference"] == -0.5
