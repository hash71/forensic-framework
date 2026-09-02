#!/usr/bin/env python3
"""Generate LaTeX result macros and vector figures from one frozen warrant run."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import defaultdict
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

_FONT_ROOT = Path("/System/Library/Fonts/Supplemental")
pdfmetrics.registerFont(TTFont("FigureSans", str(_FONT_ROOT / "Arial.ttf")))
pdfmetrics.registerFont(TTFont("FigureSansBold", str(_FONT_ROOT / "Arial Bold.ttf")))


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
        initialFontName="FigureSans",
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
        initialFontName="FigureSans",
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
    parser.add_argument("--paper-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args()
    paper_dir = args.paper_dir.resolve()
    figures = paper_dir / "figures"
    figures.mkdir(parents=True, exist_ok=True)
    write_result_macros(args.run_dir, paper_dir / "generated_results.tex")
    draw_study_design(figures / "warrant-study-design.pdf")
    draw_coverage_risk(args.run_dir / "records.jsonl", figures / "coverage-risk.pdf")
    print(paper_dir / "generated_results.tex")
    print(figures / "warrant-study-design.pdf")
    print(figures / "coverage-risk.pdf")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
