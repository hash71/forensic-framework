#!/usr/bin/env python3
"""Generate LaTeX result macros and vector figures from one frozen warrant run."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import reportlab
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean

from reportlab.lib import colors
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas


CONDITION_LABELS = {
    "llm_events_only": "Events only",
    "llm_events_plus_alerts": "Events + alerts",
    "llm_self_review": "Self-review",
    "generator_verifier": "Verifier",
    "generator_verifier_abstention": "Verifier + abstain",
}

CONDITION_STYLES = {
    "llm_events_only": (colors.HexColor("#2C5F8A"), "circle"),
    "llm_events_plus_alerts": (colors.HexColor("#A84832"), "square"),
    "llm_self_review": (colors.HexColor("#6D4C8E"), "triangle"),
    "generator_verifier": (colors.HexColor("#18786F"), "diamond"),
    "generator_verifier_abstention": (colors.HexColor("#111111"), "cross"),
}

VARIANT_LABELS = {
    "canonical": "Canonical",
    "no_alert": "No alert",
    "misleading_alert_actor": "Wrong alert actor",
    "misleading_alert_severity": "Misleading severity",
    "strong_decoy": "Strong decoy",
    "counterevidence_removed": "Counterevidence removed",
    "decisive_evidence_removed": "Decisive evidence removed",
    "irrelevant_noise": "Irrelevant noise",
    "schema_drift": "Schema drift",
    "passive_prompt_injection": "Passive prompt injection",
}

VARIANT_ORDER = tuple(VARIANT_LABELS)
AXIS_ORDER = (
    "citation",
    "actor",
    "action",
    "object",
    "temporal",
    "quantitative",
    "scope",
    "modality",
    "authorization",
    "intent",
    "causality",
    "decision",
    "evidence_relation",
)

_FONT_ROOT = Path(reportlab.__file__).resolve().parent / "fonts"
pdfmetrics.registerFont(TTFont("FigureSans", str(_FONT_ROOT / "Vera.ttf")))
pdfmetrics.registerFont(TTFont("FigureSansBold", str(_FONT_ROOT / "VeraBd.ttf")))


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pct(value: float | None) -> str:
    if value is None:
        return "--"
    return f"{100.0 * value:.1f}\\%"


def _number(value: float | None, digits: int = 3) -> str:
    if value is None:
        return "--"
    rounded = f"{value:.{digits}f}"
    if rounded.startswith("-0."):
        return "-" + rounded[2:]
    if rounded.startswith("0."):
        return rounded[1:]
    return rounded


def _compact_count(value: int | float | None) -> str:
    if value is None:
        return "--"
    number = float(value)
    if abs(number) >= 1_000_000:
        return f"{number / 1_000_000:.2f}M"
    if abs(number) >= 1_000:
        return f"{number / 1_000:.1f}K"
    return str(int(number))


def _latex_text(value: str) -> str:
    return value.replace("&", "\\&").replace("_", "\\_")


def _macro(name: str, value: str) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _load_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_result_macros(run_dir: Path, output_path: Path) -> None:
    analysis_path = run_dir / "analysis.json"
    statistics_path = run_dir / "statistics.json"
    records_path = run_dir / "records.jsonl"
    analysis = _load_json(analysis_path)
    statistics = _load_json(statistics_path)
    records = _load_records(records_path)
    conditions = analysis["conditions"]

    valid = sum(item["valid_n"] for item in conditions.values())
    total = sum(item["n"] for item in conditions.values())
    alert_pairs = analysis["paired_effects"]["events_only_vs_alerts"]
    contrasts = statistics["contrasts"]

    event = conditions["llm_events_only"]
    alerts = conditions["llm_events_plus_alerts"]
    self_review = conditions["llm_self_review"]
    verifier = conditions["generator_verifier"]
    abstain = conditions["generator_verifier_abstention"]
    unsafe = contrasts["surfaced_unwarranted_claims_per_case"]
    recall = contrasts["attack_recall"]
    coverage = contrasts["coverage"]
    secondary = statistics["exploratory_secondary_contrasts"]
    h3 = secondary[
        "h3_misleading_alerts_minus_canonical_alert_context_sensitivity"
    ]
    h4 = secondary["h4_independent_verifier_minus_self_review"]
    operations = analysis["operations"]["overall"]

    values = {
        "TestRecords": str(analysis["record_count"]),
        "TestBaseCases": str(analysis["base_case_count"]),
        "TestVariants": str(len({record["variant"] for record in records})),
        "OperationalValidity": _pct(valid / total if total else None),
        "AlertsAccuracy": _pct(alerts["verdict_accuracy"]),
        "AlertsCoverage": _pct(alerts["coverage"]),
        "AlertsAttackRecall": _pct(alerts["attack_recall"]),
        "AlertsBenignRejection": _pct(alerts["benign_rejection"]),
        "AlertsUnsafeExposure": _number(alerts["surfaced_unwarranted_decisive_claims_per_case"]),
        "AlertsRawUDCR": _pct(alerts["raw_udcr_micro"]),
        "AlertsCitationValidity": _pct(alerts["citation_validity"]),
        "EventsAccuracy": _pct(event["verdict_accuracy"]),
        "EventsCoverage": _pct(event["coverage"]),
        "EventsAttackRecall": _pct(event["attack_recall"]),
        "EventsBenignRejection": _pct(event["benign_rejection"]),
        "EventsUnsafeExposure": _number(event["surfaced_unwarranted_decisive_claims_per_case"]),
        "SelfAccuracy": _pct(self_review["verdict_accuracy"]),
        "SelfCoverage": _pct(self_review["coverage"]),
        "SelfAttackRecall": _pct(self_review["attack_recall"]),
        "SelfUnsafeExposure": _number(self_review["surfaced_unwarranted_decisive_claims_per_case"]),
        "VerifierAccuracy": _pct(verifier["verdict_accuracy"]),
        "VerifierCoverage": _pct(verifier["coverage"]),
        "VerifierAttackRecall": _pct(verifier["attack_recall"]),
        "VerifierUnsafeExposure": _number(verifier["surfaced_unwarranted_decisive_claims_per_case"]),
        "AbstainAccuracy": _pct(abstain["verdict_accuracy"]),
        "AbstainCoverage": _pct(abstain["coverage"]),
        "AbstainAttackRecall": _pct(abstain["attack_recall"]),
        "AbstainBenignRejection": _pct(abstain["benign_rejection"]),
        "AbstainUnsafeExposure": _number(abstain["surfaced_unwarranted_decisive_claims_per_case"]),
        "AbstainDeliveredUDCR": _pct(abstain["delivered_udcr_micro"]),
        "UnsafeDifference": _number(unsafe["estimate_intervention_minus_reference"]),
        "UnsafeCILow": _number(unsafe["confidence_interval"][0]),
        "UnsafeCIHigh": _number(unsafe["confidence_interval"][1]),
        "RecallDifference": _number(recall["estimate_intervention_minus_reference"]),
        "RecallCILow": _number(recall["confidence_interval"][0]),
        "RecallCIHigh": _number(recall["confidence_interval"][1]),
        "CoverageDifference": _number(coverage["estimate_intervention_minus_reference"]),
        "CoverageCILow": _number(coverage["confidence_interval"][0]),
        "CoverageCIHigh": _number(coverage["confidence_interval"][1]),
        "NoninferiorResult": "" if statistics["attack_recall_noninferiority"]["noninferior"] else "not",
        "AlertVerdictFlip": _pct(alert_pairs["verdict_flip_rate"]),
        "AlertActorFlip": _pct(alert_pairs["suspect_flip_rate"]),
        "HThreeVerdictDifference": _pct(
            h3["verdict_flip"]["estimate_intervention_minus_reference"]
        ),
        "HThreeVerdictCILow": _pct(h3["verdict_flip"]["confidence_interval"][0]),
        "HThreeVerdictCIHigh": _pct(h3["verdict_flip"]["confidence_interval"][1]),
        "HThreeActorDifference": _pct(
            h3["actor_flip"]["estimate_intervention_minus_reference"]
        ),
        "HThreeActorCILow": _pct(h3["actor_flip"]["confidence_interval"][0]),
        "HThreeActorCIHigh": _pct(h3["actor_flip"]["confidence_interval"][1]),
        "HFourWrongActorDifference": _number(
            h4["surfaced_wrong_actor"]["estimate_intervention_minus_reference"]
        ),
        "HFourWrongActorCILow": _number(
            h4["surfaced_wrong_actor"]["confidence_interval"][0]
        ),
        "HFourWrongActorCIHigh": _number(
            h4["surfaced_wrong_actor"]["confidence_interval"][1]
        ),
        "HFourContradictedDifference": _number(
            h4["surfaced_contradicted_decisive_claims"][
                "estimate_intervention_minus_reference"
            ]
        ),
        "HFourContradictedCILow": _number(
            h4["surfaced_contradicted_decisive_claims"]["confidence_interval"][0]
        ),
        "HFourContradictedCIHigh": _number(
            h4["surfaced_contradicted_decisive_claims"]["confidence_interval"][1]
        ),
        "OperationalFailures": str(total - valid),
        "UniqueModelCalls": str(operations["unique_calls"]),
        "MedianLatencySeconds": _number(
            operations["latency_ms_median"] / 1000
            if operations["latency_ms_median"] is not None else None,
            1,
        ),
        "NinetyFifthLatencySeconds": _number(
            operations["latency_ms_p95"] / 1000
            if operations["latency_ms_p95"] is not None else None,
            1,
        ),
        "InputTokens": _compact_count(operations["input_tokens_total"]),
        "OutputTokens": _compact_count(operations["output_tokens_total"]),
    }
    provenance = (
        "% Generated; do not edit by hand.\n"
        f"% run_id={analysis['run_id']}\n"
        f"% analysis_sha256={_sha256(analysis_path)}\n"
        f"% statistics_sha256={_sha256(statistics_path)}\n"
        f"% records_sha256={_sha256(records_path)}\n"
    )
    output_path.write_text(
        provenance + "\n".join(_macro(name, value) for name, value in values.items()) + "\n"
    )


def write_variant_rows(run_dir: Path, output_path: Path) -> None:
    analysis = _load_json(run_dir / "analysis.json")
    rows = []
    for variant in VARIANT_ORDER:
        group = analysis["by_variant"].get(variant)
        if group is None:
            continue
        alerts = group["conditions"]["llm_events_plus_alerts"]
        abstain = group["conditions"]["generator_verifier_abstention"]
        canonical_contrast = analysis["variant_contrasts"].get(variant, {}).get(
            "llm_events_plus_alerts"
        )
        rows.append(
            " & ".join((
                _latex_text(VARIANT_LABELS[variant]),
                _pct(alerts["verdict_accuracy"]),
                _number(alerts["surfaced_unwarranted_decisive_claims_per_case"]),
                _pct(
                    canonical_contrast["verdict_flip_rate"]
                    if canonical_contrast is not None
                    else None
                ),
                _pct(abstain["coverage"]),
                _number(abstain["surfaced_unwarranted_decisive_claims_per_case"]),
            )) + " \\\\"
        )
    output_path.write_text(
        "% Generated from analysis.json; descriptive variant rows.\n"
        + "\n".join(rows)
        + "\n\\bottomrule\n"
    )


def write_axis_rows(run_dir: Path, output_path: Path) -> None:
    analysis = _load_json(run_dir / "analysis.json")
    axes = analysis["mechanical_axis_profiles"]["llm_events_plus_alerts"][
        "decisive_claims"
    ]
    rows = []
    for axis in AXIS_ORDER:
        if axis not in axes:
            continue
        item = axes[axis]
        rows.append(
            f"{_latex_text(axis.replace('_', ' '))} & {item['applicable']} & "
            f"{_pct(item['unwarranted_rate'])} \\\\"
        )
    output_path.write_text(
        "% Generated from analysis.json; mechanical descriptive labels only.\n"
        + "\n".join(rows)
        # Keep the final booktabs rule in the included file. XeTeX can leave
        # the alignment row open when a row-only input ends immediately before
        # a caller-side \bottomrule, producing a misleading ``Misplaced
        # \noalign`` error.
        + "\n\\bottomrule\n"
    )


def write_external_result_macros(run_dir: Path, output_path: Path) -> None:
    """Write macros for the label-honest CERT transfer stress test."""

    analysis_path = run_dir / "analysis.json"
    records_path = run_dir / "records.jsonl"
    analysis = _load_json(analysis_path)
    records = _load_records(records_path)
    semantics = {record.get("evaluation_label_semantics") for record in records}
    expected = {"latent_incident_label_not_visible_evidence_warrant"}
    if semantics != expected:
        raise ValueError(
            f"external run has unexpected label semantics: {sorted(semantics)}"
        )
    conditions = analysis["conditions"]
    base = conditions["llm_events_plus_alerts"]
    verifier = conditions["generator_verifier"]
    abstain = conditions["generator_verifier_abstention"]
    valid = sum(item["valid_n"] for item in conditions.values())
    total = sum(item["n"] for item in conditions.values())
    generator_attempts = {}
    for record in records:
        generator = record.get("generator") or {}
        call = generator.get("call") or {}
        key = call.get("raw_response_path") or (
            f"{record['case_id']}:{record['repetition']}"
        )
        generator_attempts.setdefault(key, generator)
    generator_error_types = Counter(
        (generator.get("error") or {}).get("type")
        for generator in generator_attempts.values()
        if generator.get("error")
    )
    values = {
        "ExternalRecords": str(analysis["record_count"]),
        "ExternalClusters": str(analysis["base_case_count"]),
        "ExternalWindows": str(len({record["case_id"] for record in records})),
        "ExternalOperationalValidity": _pct(valid / total if total else None),
        "ExternalOperationalFailure": _pct(1.0 - valid / total if total else None),
        "ExternalGeneratorAttempts": str(len(generator_attempts)),
        "ExternalJSONFailures": str(generator_error_types["JSONDecodeError"]),
        "ExternalSchemaFailures": str(generator_error_types["ValidationError"]),
        "ExternalBaseAccuracy": _pct(base["verdict_accuracy"]),
        "ExternalBaseCoverage": _pct(base["coverage"]),
        "ExternalBaseAttackRecall": _pct(base["attack_recall"]),
        "ExternalBaseBenignRejection": _pct(base["benign_rejection"]),
        "ExternalBaseUnsafeExposure": _number(
            base["surfaced_unwarranted_decisive_claims_per_case"]
        ),
        "ExternalBaseCitationValidity": _pct(base["citation_validity"]),
        "ExternalVerifierAccuracy": _pct(verifier["verdict_accuracy"]),
        "ExternalVerifierCoverage": _pct(verifier["coverage"]),
        "ExternalVerifierAttackRecall": _pct(verifier["attack_recall"]),
        "ExternalVerifierBenignRejection": _pct(verifier["benign_rejection"]),
        "ExternalVerifierUnsafeExposure": _number(
            verifier["surfaced_unwarranted_decisive_claims_per_case"]
        ),
        "ExternalAbstainAccuracy": _pct(abstain["verdict_accuracy"]),
        "ExternalAbstainCoverage": _pct(abstain["coverage"]),
        "ExternalAbstainAttackRecall": _pct(abstain["attack_recall"]),
        "ExternalAbstainBenignRejection": _pct(abstain["benign_rejection"]),
        "ExternalAbstainUnsafeExposure": _number(
            abstain["surfaced_unwarranted_decisive_claims_per_case"]
        ),
    }
    provenance = (
        "% Generated; do not edit by hand.\n"
        f"% run_id={analysis['run_id']}\n"
        f"% analysis_sha256={_sha256(analysis_path)}\n"
        f"% records_sha256={_sha256(records_path)}\n"
    )
    output_path.write_text(
        provenance + "\n".join(_macro(name, value) for name, value in values.items()) + "\n"
    )


def write_human_result_macros(analysis_path: Path, output_path: Path) -> None:
    """Write macros from a checksum-bound, adjudicated human audit."""

    analysis = _load_json(analysis_path)
    inter = analysis["inter_rater"]["overall"]
    mechanical = analysis["mechanical_validation"]["overall"]
    flag = analysis["mechanical_validation"]["materially_unwarranted_flag"]
    intervals = analysis["bootstrap"]["metrics"]
    human_agreement_ci = intervals["inter_rater_overall_agreement"][
        "confidence_interval"
    ]
    mechanical_agreement_ci = intervals["mechanical_overall_agreement"][
        "confidence_interval"
    ]
    precision_ci = intervals["materially_unwarranted_precision"][
        "confidence_interval"
    ]
    recall_ci = intervals["materially_unwarranted_recall"]["confidence_interval"]
    primary = analysis["human_primary_endpoint"]
    primary_reference = primary["condition_estimates"][
        primary["reference_condition"]
    ]
    primary_intervention = primary["condition_estimates"][
        primary["intervention_condition"]
    ]
    primary_contrast = primary["contrast_intervention_minus_reference"]
    timing = analysis["annotation_timing"]
    values = {
        "HumanSampleClaims": str(analysis["sample"]["selected_claims"]),
        "HumanPopulationClaims": str(analysis["sample"]["population_claims"]),
        "HumanRawAgreement": _pct(inter["agreement"]),
        "HumanWeightedAgreement": _pct(inter["design_weighted_agreement"]),
        "HumanWeightedAgreementCILow": _pct(human_agreement_ci[0]),
        "HumanWeightedAgreementCIHigh": _pct(human_agreement_ci[1]),
        "HumanKappa": _number(inter["cohen_kappa"]),
        "HumanWeightedKappa": _number(inter["design_weighted_cohen_kappa"]),
        "HumanMaterialityWeightedAgreement": _pct(
            analysis["inter_rater"]["materiality_decisive"][
                "design_weighted_agreement"
            ]
        ),
        "MechanicalHumanAgreement": _pct(mechanical["agreement"]),
        "MechanicalHumanWeightedAgreement": _pct(
            mechanical["design_weighted_agreement"]
        ),
        "MechanicalHumanWeightedAgreementCILow": _pct(
            mechanical_agreement_ci[0]
        ),
        "MechanicalHumanWeightedAgreementCIHigh": _pct(
            mechanical_agreement_ci[1]
        ),
        "MechanicalHumanKappa": _number(
            mechanical["design_weighted_cohen_kappa"]
        ),
        "MechanicalMaterialityWeightedAgreement": _pct(
            analysis["mechanical_validation"]["materiality_decisive"][
                "design_weighted_agreement"
            ]
        ),
        "MechanicalFlagPrecision": _pct(flag["design_weighted_precision"]),
        "MechanicalFlagPrecisionCILow": _pct(precision_ci[0]),
        "MechanicalFlagPrecisionCIHigh": _pct(precision_ci[1]),
        "MechanicalFlagRecall": _pct(flag["design_weighted_recall"]),
        "MechanicalFlagRecallCILow": _pct(recall_ci[0]),
        "MechanicalFlagRecallCIHigh": _pct(recall_ci[1]),
        "MechanicalFlagSpecificity": _pct(flag["design_weighted_specificity"]),
        "MechanicalFlagFOne": _pct(flag["design_weighted_f1"]),
        "HumanPrimaryJoinedClaims": str(
            primary["selected_claims_joined_to_primary_conditions"]
        ),
        "HumanPrimaryAlertsUnsafeExposure": _number(
            primary_reference[
                "surfaced_unwarranted_decisive_claims_per_base_case"
            ]
        ),
        "HumanPrimaryAbstainUnsafeExposure": _number(
            primary_intervention[
                "surfaced_unwarranted_decisive_claims_per_base_case"
            ]
        ),
        "HumanPrimaryUnsafeDifference": _number(primary_contrast["estimate"]),
        "HumanPrimaryUnsafeCILow": _number(
            primary_contrast["confidence_interval"][0]
        ),
        "HumanPrimaryUnsafeCIHigh": _number(
            primary_contrast["confidence_interval"][1]
        ),
        "AnnotatorOneMedianMinutes": _number(
            timing["annotator_1"]["median_seconds_per_item"] / 60.0
        ),
        "AnnotatorTwoMedianMinutes": _number(
            timing["annotator_2"]["median_seconds_per_item"] / 60.0
        ),
        "AdjudicatorMedianMinutes": _number(
            timing["adjudicator"]["median_seconds_per_item"] / 60.0
        ),
        "AnnotationTotalHours": _number(sum(
            timing[role]["total_hours"]
            for role in ("annotator_1", "annotator_2", "adjudicator")
        )),
    }
    provenance = (
        "% Generated; do not edit by hand.\n"
        f"% human_analysis_sha256={_sha256(analysis_path)}\n"
        f"% source_records_sha256={analysis['source_sha256']['records']}\n"
    )
    output_path.write_text(
        provenance
        + "\n".join(_macro(name, value) for name, value in values.items())
        + "\n"
    )


def write_simulated_result_macros(analysis_path: Path, output_path: Path) -> None:
    """Write explicitly non-human AI-panel sensitivity macros."""

    analysis = _load_json(analysis_path)
    if "not expert validation" not in analysis["validity_boundary"]:
        raise ValueError("simulated analysis lacks the required validity boundary")
    sample = analysis["sample"]
    panel = analysis["panel"]
    proxy = analysis["consensus_vs_mechanical_proxy"]
    flag = proxy["materially_unwarranted_flag"]
    primary = analysis["simulated_primary_endpoint"]
    reference = primary["condition_estimates"][primary["reference_condition"]]
    intervention = primary["condition_estimates"][primary["intervention_condition"]]
    contrast = primary["contrast_intervention_minus_reference"]
    reviewer_differences = [
        endpoint["contrast_intervention_minus_reference"]["estimate"]
        for endpoint in analysis["individual_reviewer_sensitivity_endpoints"].values()
    ]
    values = {
        "SimPanelClaims": str(sample["claims"]),
        "SimPanelPopulationClaims": str(sample["population_claims"]),
        "SimPanelReviewers": str(sum(
            reviewer["panel_role"] == "consensus"
            for reviewer in analysis["reviewers"]
        )),
        "SimPanelCoreConsensusClaims": str(panel["items_with_core_consensus"]),
        "SimPanelCompleteConsensusClaims": str(
            panel["items_with_complete_field_consensus"]
        ),
        "SimPanelUnresolvedOverall": str(
            panel["items_without_overall_consensus"]
        ),
        "SimPanelAnyDisagreement": _pct(
            panel["items_with_any_disagreement"] / sample["claims"]
        ),
        "SimPanelOverallDisagreement": _pct(
            panel["items_with_overall_disagreement"] / sample["claims"]
        ),
        "SimPanelMaterialityDisagreement": _pct(
            panel["items_with_materiality_disagreement"] / sample["claims"]
        ),
        "SimMechanicalWeightedAgreement": _pct(
            proxy["overall"]["design_weighted_agreement"]
        ),
        "SimMechanicalWeightedKappa": _number(
            proxy["overall"]["design_weighted_cohen_kappa"]
        ),
        "SimFlagPrecision": _pct(flag["design_weighted_precision"]),
        "SimFlagRecall": _pct(flag["design_weighted_recall"]),
        "SimPrimaryJoinedClaims": str(
            primary["selected_claims_joined_to_primary_conditions"]
        ),
        "SimPrimaryAlertsUnsafeExposure": _number(
            reference["surfaced_unwarranted_decisive_claims_per_base_case"]
        ),
        "SimPrimaryAbstainUnsafeExposure": _number(
            intervention["surfaced_unwarranted_decisive_claims_per_base_case"]
        ),
        "SimPrimaryUnsafeDifference": _number(contrast["estimate"]),
        "SimPrimaryUnsafeCILow": _number(contrast["confidence_interval"][0]),
        "SimPrimaryUnsafeCIHigh": _number(contrast["confidence_interval"][1]),
        "SimReviewerUnsafeDifferenceLow": _number(min(reviewer_differences)),
        "SimReviewerUnsafeDifferenceHigh": _number(max(reviewer_differences)),
    }
    provenance = (
        "% Generated; AI-panel sensitivity evidence only, not expert validation.\n"
        f"% simulated_analysis_sha256={_sha256(analysis_path)}\n"
        f"% source_records_sha256={analysis['source_sha256']['records']}\n"
    )
    output_path.write_text(
        provenance
        + "\n".join(_macro(name, value) for name, value in values.items())
        + "\n"
    )


def _rounded_box(
    pdf: canvas.Canvas,
    x: float,
    y: float,
    width: float,
    height: float,
    title: str,
    subtitle: str,
    *,
    fill: colors.Color,
    border: colors.Color = colors.HexColor("#263238"),
) -> None:
    pdf.setStrokeColor(border)
    pdf.setFillColor(fill)
    pdf.setLineWidth(1.0)
    pdf.roundRect(x, y, width, height, 6, stroke=1, fill=1)
    pdf.setFillColor(colors.HexColor("#111111"))
    pdf.setFont("FigureSansBold", 8.7)
    pdf.drawCentredString(x + width / 2, y + height - 15, title)
    pdf.setFont("FigureSans", 7.2)
    for index, line in enumerate(subtitle.split("\n")):
        pdf.drawCentredString(x + width / 2, y + height - 28 - index * 9, line)


def _arrow(pdf: canvas.Canvas, x1: float, y1: float, x2: float, y2: float, *, dashed: bool = False) -> None:
    pdf.saveState()
    pdf.setStrokeColor(colors.HexColor("#37474F"))
    pdf.setFillColor(colors.HexColor("#37474F"))
    pdf.setLineWidth(1.1)
    if dashed:
        pdf.setDash(4, 3)
    pdf.line(x1, y1, x2, y2)
    dx, dy = x2 - x1, y2 - y1
    length = max((dx * dx + dy * dy) ** 0.5, 1.0)
    ux, uy = dx / length, dy / length
    px, py = -uy, ux
    size = 5.0
    pdf.line(x2, y2, x2 - size * ux + 2.3 * px, y2 - size * uy + 2.3 * py)
    pdf.line(x2, y2, x2 - size * ux - 2.3 * px, y2 - size * uy - 2.3 * py)
    pdf.restoreState()


def draw_study_design(path: Path) -> None:
    width, height = 7.0 * 72, 2.35 * 72
    pdf = canvas.Canvas(
        str(path), pagesize=(width, height), pageCompression=1,
        initialFontName="FigureSans", invariant=1,
    )
    pdf.setTitle("Paired forensic warrant study design")

    _rounded_box(pdf, 10, 56, 78, 62, "VISIBLE CASE", "events + baselines\nalerts are untrusted", fill=colors.HexColor("#E8EEF3"))
    _rounded_box(pdf, 112, 98, 90, 48, "EVENTS-ONLY", "independent generation", fill=colors.HexColor("#E9F1FA"))
    _rounded_box(pdf, 112, 29, 90, 55, "ALERT-VISIBLE", "one shared generation\n(raw hash fixed)", fill=colors.HexColor("#FBEDE8"))
    _rounded_box(pdf, 238, 104, 84, 42, "DELIVER", "unreviewed output", fill=colors.HexColor("#F4F4F4"))
    _rounded_box(pdf, 238, 55, 84, 42, "SELF-REVIEW", "same model/context", fill=colors.HexColor("#F0EAF6"))
    _rounded_box(pdf, 238, 6, 84, 42, "ALERT-BLIND", "shared verifier call", fill=colors.HexColor("#E6F3F1"))
    _rounded_box(pdf, 358, 55, 132, 42, "VERIFIER OUTPUT", "review disposition", fill=colors.HexColor("#E6F3F1"))
    _rounded_box(pdf, 358, 6, 132, 42, "SELECTIVE POLICY", "deliver or abstain", fill=colors.HexColor("#ECECEC"))

    _arrow(pdf, 88, 99, 112, 122)
    _arrow(pdf, 88, 75, 112, 57, dashed=True)
    _arrow(pdf, 202, 57, 238, 125)
    _arrow(pdf, 202, 57, 238, 76)
    _arrow(pdf, 202, 57, 238, 27)
    _arrow(pdf, 322, 27, 358, 76)
    _arrow(pdf, 322, 27, 358, 27)
    _arrow(pdf, 424, 55, 424, 48)

    pdf.setFillColor(colors.HexColor("#455A64"))
    pdf.setFont("FigureSans", 6.8)
    pdf.drawString(10, 16, "Solid: evidence flow")
    pdf.setDash(4, 3)
    pdf.line(10, 8, 40, 8)
    pdf.setDash()
    pdf.drawString(45, 5.5, "Dashed: alert-conditioned path")
    pdf.save()


def _record_metric(record: dict, metric: str) -> float:
    if metric == "coverage":
        return float(
            record["operational_status"].startswith("valid")
            and record.get("predicted_verdict") != "INSUFFICIENT"
        )
    if metric == "unsafe":
        if not record["operational_status"].startswith("valid"):
            return 0.0
        if record.get("predicted_verdict") == "INSUFFICIENT":
            return 0.0
        warrant = record.get("mechanical_warrant") or {}
        return float(sum(
            item["decisive"] and item["overall_label"] != "SUPPORTED"
            for item in warrant.get("assessments", [])
        ))
    raise ValueError(metric)


def _cluster_values(records: list[dict], condition: str, metric: str) -> list[float]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for record in records:
        if record["condition"] == condition:
            grouped[record["base_case_id"]].append(_record_metric(record, metric))
    return [mean(grouped[key]) for key in sorted(grouped)]


def _bootstrap_interval(values: list[float], seed: int, repetitions: int = 10_000) -> tuple[float, float, float]:
    estimate = mean(values)
    rng = random.Random(seed)
    size = len(values)
    samples = sorted(mean(values[rng.randrange(size)] for _ in range(size)) for _ in range(repetitions))
    return estimate, samples[int(0.025 * repetitions)], samples[int(0.975 * repetitions) - 1]


def _draw_marker(pdf: canvas.Canvas, x: float, y: float, shape: str, color: colors.Color) -> None:
    pdf.setStrokeColor(color)
    pdf.setFillColor(color)
    pdf.setLineWidth(1.4)
    size = 3.8
    if shape == "circle":
        pdf.circle(x, y, size, stroke=1, fill=1)
    elif shape == "square":
        pdf.rect(x - size, y - size, 2 * size, 2 * size, stroke=1, fill=1)
    elif shape == "triangle":
        path = pdf.beginPath()
        path.moveTo(x, y + size + 1)
        path.lineTo(x - size - 1, y - size)
        path.lineTo(x + size + 1, y - size)
        path.close()
        pdf.drawPath(path, stroke=1, fill=1)
    elif shape == "diamond":
        path = pdf.beginPath()
        path.moveTo(x, y + size + 1)
        path.lineTo(x - size - 1, y)
        path.lineTo(x, y - size - 1)
        path.lineTo(x + size + 1, y)
        path.close()
        pdf.drawPath(path, stroke=1, fill=1)
    else:
        pdf.line(x - size, y - size, x + size, y + size)
        pdf.line(x - size, y + size, x + size, y - size)


def draw_coverage_risk(records_path: Path, output_path: Path) -> None:
    records = _load_records(records_path)
    width, height = 3.35 * 72, 2.75 * 72
    left, right, bottom, top = 39, 8, 31, 32
    plot_w, plot_h = width - left - right, height - bottom - top
    points = {}
    max_unsafe = 0.0
    for index, condition in enumerate(CONDITION_LABELS):
        coverage = _bootstrap_interval(_cluster_values(records, condition, "coverage"), 9100 + index)
        unsafe = _bootstrap_interval(_cluster_values(records, condition, "unsafe"), 9200 + index)
        points[condition] = (coverage, unsafe)
        max_unsafe = max(max_unsafe, unsafe[2])
    y_max = max(0.25, max_unsafe * 1.12)

    def sx(value: float) -> float:
        return left + value * plot_w

    def sy(value: float) -> float:
        return bottom + value / y_max * plot_h

    pdf = canvas.Canvas(
        str(output_path), pagesize=(width, height), pageCompression=1,
        initialFontName="FigureSans", invariant=1,
    )
    pdf.setTitle("Coverage versus unsafe claim exposure")
    legend = [
        ("llm_events_only", "Events", 42, height - 10),
        ("llm_events_plus_alerts", "+Alerts", 112, height - 10),
        ("llm_self_review", "Self-review", 180, height - 10),
        ("generator_verifier", "Verifier", 76, height - 22),
        ("generator_verifier_abstention", "+Abstain", 154, height - 22),
    ]
    for condition, label, x, y in legend:
        color, shape = CONDITION_STYLES[condition]
        _draw_marker(pdf, x, y, shape, color)
        pdf.setFillColor(colors.HexColor("#111111"))
        pdf.setFont("FigureSans", 6.5)
        pdf.drawString(x + 6, y - 2.2, label)
    pdf.setStrokeColor(colors.HexColor("#B0BEC5"))
    pdf.setLineWidth(0.35)
    for tick in (0.0, 0.25, 0.50, 0.75, 1.0):
        x = sx(tick)
        pdf.line(x, bottom, x, bottom + plot_h)
        pdf.setFillColor(colors.HexColor("#37474F"))
        pdf.setFont("FigureSans", 6.8)
        pdf.drawCentredString(x, bottom - 11, f"{tick:.2f}")
    for index in range(5):
        value = y_max * index / 4
        y = sy(value)
        pdf.setStrokeColor(colors.HexColor("#CFD8DC"))
        pdf.line(left, y, left + plot_w, y)
        pdf.setFillColor(colors.HexColor("#37474F"))
        pdf.setFont("FigureSans", 6.8)
        label = f"{value:.2f}"
        pdf.drawRightString(left - 4, y - 2.3, label)
    pdf.setStrokeColor(colors.HexColor("#263238"))
    pdf.setLineWidth(0.8)
    pdf.line(left, bottom, left + plot_w, bottom)
    pdf.line(left, bottom, left, bottom + plot_h)
    pdf.setFont("FigureSans", 7.3)
    pdf.setFillColor(colors.HexColor("#111111"))
    pdf.drawCentredString(left + plot_w / 2, 7, "Coverage")
    pdf.saveState()
    pdf.translate(9, bottom + plot_h / 2)
    pdf.rotate(90)
    pdf.drawCentredString(0, 0, "Unsafe decisive claims / case")
    pdf.restoreState()

    for condition, (coverage, unsafe) in points.items():
        x, y = sx(coverage[0]), sy(unsafe[0])
        xlo, xhi = sx(coverage[1]), sx(coverage[2])
        ylo, yhi = sy(unsafe[1]), sy(unsafe[2])
        color, shape = CONDITION_STYLES[condition]
        pdf.setStrokeColor(color)
        pdf.setLineWidth(0.8)
        pdf.line(xlo, y, xhi, y)
        pdf.line(xlo, y - 2, xlo, y + 2)
        pdf.line(xhi, y - 2, xhi, y + 2)
        pdf.line(x, ylo, x, yhi)
        pdf.line(x - 2, ylo, x + 2, ylo)
        pdf.line(x - 2, yhi, x + 2, yhi)
        _draw_marker(pdf, x, y, shape, color)
    pdf.save()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--external-run-dir", type=Path)
    parser.add_argument("--human-analysis", type=Path)
    parser.add_argument("--simulated-analysis", type=Path)
    parser.add_argument("--paper-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    paper_dir = args.paper_dir.resolve()
    figures = paper_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    write_result_macros(args.run_dir, paper_dir / "generated_results.tex")
    write_variant_rows(args.run_dir, paper_dir / "generated_variant_rows.tex")
    write_axis_rows(args.run_dir, paper_dir / "generated_axis_rows.tex")
    draw_study_design(figures / "warrant-study-design.pdf")
    draw_coverage_risk(args.run_dir / "records.jsonl", figures / "coverage-risk.pdf")
    if args.external_run_dir is not None:
        write_external_result_macros(
            args.external_run_dir,
            paper_dir / "generated_external_results.tex",
        )
    else:
        (paper_dir / "generated_external_results.tex").unlink(missing_ok=True)
    if args.human_analysis is not None:
        write_human_result_macros(
            args.human_analysis,
            paper_dir / "generated_human_results.tex",
        )
    else:
        (paper_dir / "generated_human_results.tex").unlink(missing_ok=True)
    if args.simulated_analysis is not None:
        write_simulated_result_macros(
            args.simulated_analysis,
            paper_dir / "generated_simulated_results.tex",
        )
    else:
        (paper_dir / "generated_simulated_results.tex").unlink(missing_ok=True)
    print(paper_dir / "generated_results.tex")
    print(paper_dir / "generated_variant_rows.tex")
    print(paper_dir / "generated_axis_rows.tex")
    print(figures / "warrant-study-design.pdf")
    print(figures / "coverage-risk.pdf")
    if args.external_run_dir is not None:
        print(paper_dir / "generated_external_results.tex")
    if args.human_analysis is not None:
        print(paper_dir / "generated_human_results.tex")
    if args.simulated_analysis is not None:
        print(paper_dir / "generated_simulated_results.tex")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
