"""
Forensic Report Generator

Generates comprehensive forensic investigation reports for each scenario
by combining rule engine results, LLM analysis, correlation findings,
timeline data, and evaluation metrics.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
NORMALIZED_DIR = DATA_DIR / "normalized"
LLM_DIR = DATA_DIR / "llm_responses"
REPORTS_DIR = DATA_DIR / "reports"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth" / "ground_truth.json"
EVALUATION_PATH = DATA_DIR / "evaluation_results.json"
BASELINES_PATH = DATA_DIR / "user_baselines.json"


def _load_json(path: Path) -> Optional[dict | list]:
    """Load a JSON file, returning None if it does not exist."""
    if not path.exists():
        print(f"  [WARNING] File not found: {path}")
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _get_ground_truth() -> dict:
    """Load ground truth data, indexed by scenario number."""
    gt = _load_json(GROUND_TRUTH_PATH)
    if gt is None:
        return {}
    result = {}
    for sc in gt.get("scenarios", []):
        num = int(sc["id"].split("_")[1])
        result[num] = sc
    return result


def _get_evaluation_results() -> dict:
    """Load evaluation results, indexed by scenario number."""
    data = _load_json(EVALUATION_PATH)
    if data is None:
        return {}
    return {entry["scenario"]: entry for entry in data}


def _map_verdict_to_label(verdict: str) -> str:
    """Map a rule or LLM verdict string to BENIGN or ATTACK."""
    attack_verdicts = {"attack", "yes", "suspicious"}
    benign_verdicts = {"no_alert", "no", "benign", "insufficient"}
    v = verdict.strip().lower()
    if v in attack_verdicts:
        return "ATTACK"
    if v in benign_verdicts:
        return "BENIGN"
    return "UNKNOWN"


def generate_executive_summary(
    scenario_num: int, rule_data: dict, llm_data: dict, gt_label: str
) -> str:
    """Generate a natural-language executive summary for a scenario.

    For BENIGN scenarios, notes the false-positive behavior.
    For ATTACK scenarios, describes the attack.
    References specific users and key events.
    """
    rule_verdict = rule_data.get("verdict", "unknown")
    llm_verdict = llm_data.get("verdict", "unknown")
    llm_narrative = llm_data.get("narrative", "")
    suspect = llm_data.get("suspect")
    alert_count = rule_data.get("alert_count", 0)
    rules_triggered = rule_data.get("rules_triggered", [])

    if gt_label == "BENIGN":
        if alert_count > 0:
            summary = (
                f"Scenario {scenario_num} represents benign activity that triggered "
                f"{alert_count} rule-based alert(s) ({', '.join(rules_triggered)}), "
                f"constituting false positives. "
                f"The LLM analysis correctly assessed the activity with verdict "
                f"'{llm_verdict}', confirming no genuine security incident occurred. "
                f"{llm_narrative}"
            )
        else:
            summary = (
                f"Scenario {scenario_num} represents normal baseline activity with no "
                f"alerts triggered by the rule engine (verdict: '{rule_verdict}'). "
                f"The LLM analysis concurred with verdict '{llm_verdict}'. "
                f"{llm_narrative}"
            )
    else:  # ATTACK
        chain_desc = ""
        attack_chain = llm_data.get("attack_chain", [])
        if attack_chain:
            chain_steps = []
            for step in attack_chain:
                if isinstance(step, dict):
                    chain_steps.append(step.get("description", str(step)))
                else:
                    chain_steps.append(str(step))
            chain_desc = f" The attack chain involved: {'; '.join(chain_steps)}."

        suspect_desc = f" The primary suspect is {suspect}." if suspect else ""
        summary = (
            f"Scenario {scenario_num} is a confirmed security incident. "
            f"The rule engine raised {alert_count} alert(s) with verdict "
            f"'{rule_verdict}', and the LLM analysis independently concluded "
            f"'{llm_verdict}' with confidence '{llm_data.get('confidence', 'N/A')}'.{suspect_desc}{chain_desc} "
            f"{llm_narrative}"
        )

    return summary.strip()


def generate_recommendations(
    scenario_num: int, rule_data: dict, llm_data: dict
) -> list[str]:
    """Generate 3-5 actionable recommendations based on findings."""
    recommendations = []
    rule_verdict = _map_verdict_to_label(rule_data.get("verdict", ""))
    llm_verdict = _map_verdict_to_label(llm_data.get("verdict", ""))
    alerts = rule_data.get("alerts", [])
    gaps = llm_data.get("gaps", [])
    severity = rule_data.get("severity_summary", {})

    # Recommendation based on attack detection
    if rule_verdict == "ATTACK" or llm_verdict == "ATTACK":
        suspect = llm_data.get("suspect")
        if suspect:
            recommendations.append(
                f"Immediately isolate and investigate the account '{suspect}'. "
                f"Revoke active sessions and reset credentials."
            )
        if severity.get("critical", 0) > 0:
            recommendations.append(
                "Conduct a full incident response procedure for the critical-severity "
                "alerts identified, including forensic imaging of affected systems."
            )
        # Check for privilege escalation
        priv_alerts = [a for a in alerts if "privilege" in a.get("rule_name", "").lower()]
        if priv_alerts:
            recommendations.append(
                "Review and tighten privilege escalation controls. Implement "
                "just-in-time access provisioning and mandatory approval workflows "
                "for role changes."
            )
        # Check for bulk download
        bulk_alerts = [a for a in alerts if "bulk" in a.get("rule_name", "").lower() or "download" in a.get("rule_name", "").lower()]
        if bulk_alerts:
            recommendations.append(
                "Implement data loss prevention (DLP) controls to detect and block "
                "bulk file exfiltration. Set download rate limits for sensitive directories."
            )
    elif rule_verdict == "BENIGN" and llm_verdict == "BENIGN":
        if rule_data.get("alert_count", 0) > 0:
            recommendations.append(
                "Tune rule engine thresholds to reduce false positive alerts. "
                "Consider adding contextual conditions (e.g., user role, time patterns) "
                "to existing rules."
            )
        recommendations.append(
            "Continue monitoring user activity baselines and update them periodically "
            "to reflect legitimate changes in work patterns."
        )

    # Investigative gaps
    if gaps:
        gap_text = gaps[0] if len(gaps) == 1 else gaps[0]
        recommendations.append(
            f"Address identified investigative gap: {gap_text}"
        )

    # Disagreement between rule and LLM
    if rule_verdict != llm_verdict:
        recommendations.append(
            "Investigate the disagreement between rule-based and LLM verdicts. "
            "Determine which approach was more accurate and calibrate accordingly."
        )

    # Ensure we have at least 3
    baseline_recs = [
        "Enrich logging coverage to include network traffic, process execution, "
        "and endpoint telemetry for more comprehensive forensic analysis.",
        "Schedule periodic red-team exercises to validate detection capabilities "
        "across both rule-based and LLM-assisted analysis pipelines.",
        "Establish a formal evidence chain-of-custody process for all forensic "
        "artifacts collected during investigations.",
    ]
    for rec in baseline_recs:
        if len(recommendations) >= 5:
            break
        if rec not in recommendations:
            recommendations.append(rec)

    return recommendations[:5]


def generate_scenario_report(scenario_num: int) -> dict:
    """Load all data for a scenario and produce a structured forensic report."""
    # Load all data sources
    events = _load_json(NORMALIZED_DIR / f"scenario_{scenario_num}_events.json") or []
    timeline = _load_json(NORMALIZED_DIR / f"scenario_{scenario_num}_timeline.json") or {}
    rule_data = _load_json(NORMALIZED_DIR / f"scenario_{scenario_num}_rule_results.json") or {}
    correlations = _load_json(NORMALIZED_DIR / f"scenario_{scenario_num}_correlations.json") or {}
    llm_data = _load_json(LLM_DIR / f"scenario_{scenario_num}_response.json") or {}
    gt_map = _get_ground_truth()
    eval_map = _get_evaluation_results()

    gt_entry = gt_map.get(scenario_num, {})
    eval_entry = eval_map.get(scenario_num, {})
    gt_label = gt_entry.get("label", "UNKNOWN")

    # Build timeline summary
    time_range = timeline.get("time_range", {})
    by_user = timeline.get("by_user", {})
    by_session = timeline.get("by_session", {})
    total_events = timeline.get("total_events", len(events))

    # Build rule analysis
    alerts = rule_data.get("alerts", [])
    severity_summary = rule_data.get("severity_summary", {})
    rules_triggered = rule_data.get("rules_triggered", [])

    # Key findings: pick the most important alerts (critical first, then warning)
    critical_alerts = [a for a in alerts if a.get("severity") == "critical"]
    warning_alerts = [a for a in alerts if a.get("severity") == "warning"]
    key_alerts = critical_alerts[:3] + warning_alerts[:2]
    key_findings = [a["description"] for a in key_alerts]

    # Evaluation / evidence integrity
    llm_quality = eval_entry.get("llm_quality", {})
    hallucination_report = eval_entry.get("hallucination_report", {})
    event_refs = hallucination_report.get("event_references", {})

    # Comparative assessment
    verdict_acc = eval_entry.get("verdict_accuracy", {})
    rule_correct = verdict_acc.get("rule_correct", None)
    llm_correct = verdict_acc.get("llm_correct", None)
    rule_mapped = verdict_acc.get("rule_mapped", "")
    llm_mapped = verdict_acc.get("llm_mapped", "")
    agreement = rule_mapped == llm_mapped

    # Determine LLM added value
    llm_added_value = _compute_llm_added_value(
        scenario_num, rule_data, llm_data, eval_entry, gt_label
    )

    # Executive summary
    exec_summary = generate_executive_summary(scenario_num, rule_data, llm_data, gt_label)

    # Recommendations
    recommendations = generate_recommendations(scenario_num, rule_data, llm_data)

    report = {
        "report_id": f"FR-2026-{scenario_num:03d}",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": "CONFIDENTIAL",
        "scenario": {
            "id": f"scenario_{scenario_num}",
            "name": gt_entry.get("name", f"scenario_{scenario_num}"),
            "ground_truth": gt_label,
        },
        "executive_summary": exec_summary,
        "timeline_summary": {
            "total_events": total_events,
            "time_range": {
                "start": time_range.get("start", "N/A"),
                "end": time_range.get("end", "N/A"),
            },
            "users_involved": list(by_user.keys()),
            "sessions": len(by_session),
        },
        "rule_analysis": {
            "verdict": rule_data.get("verdict", "N/A"),
            "alert_count": rule_data.get("alert_count", 0),
            "rules_triggered": rules_triggered,
            "severity_breakdown": {
                "critical": severity_summary.get("critical", 0),
                "warning": severity_summary.get("warning", 0),
            },
            "key_findings": key_findings,
        },
        "llm_analysis": {
            "verdict": llm_data.get("verdict", "N/A"),
            "confidence": llm_data.get("confidence", "N/A"),
            "suspect": llm_data.get("suspect"),
            "narrative": llm_data.get("narrative", ""),
            "attack_chain": llm_data.get("attack_chain", []),
            "evidence_for": llm_data.get("evidence_for", []),
            "evidence_against": llm_data.get("evidence_against", []),
            "investigative_gaps": llm_data.get("gaps", []),
        },
        "comparative_assessment": {
            "rule_vs_llm_agreement": agreement,
            "rule_verdict_correct": rule_correct,
            "llm_verdict_correct": llm_correct,
            "llm_added_value": llm_added_value,
        },
        "evidence_integrity": {
            "hallucination_count": llm_quality.get("hallucination_count", 0),
            "evidence_grounding_pct": llm_quality.get("evidence_grounding_pct", 0.0),
            "timeline_correct": llm_quality.get("timeline_correct", False),
            "all_references_valid": event_refs.get("hallucinated_events", 0) == 0,
        },
        "recommendations": recommendations,
        "appendix": {
            "all_events": events if isinstance(events, list) else [],
            "all_alerts": alerts,
        },
    }

    return report


def _compute_llm_added_value(
    scenario_num: int,
    rule_data: dict,
    llm_data: dict,
    eval_entry: dict,
    gt_label: str,
) -> str:
    """Describe what the LLM found that rules missed, or vice versa."""
    rule_mapped = _map_verdict_to_label(rule_data.get("verdict", ""))
    llm_mapped = _map_verdict_to_label(llm_data.get("verdict", ""))
    rule_correct = eval_entry.get("verdict_accuracy", {}).get("rule_correct")
    llm_correct = eval_entry.get("verdict_accuracy", {}).get("llm_correct")
    fp_count = eval_entry.get("false_positives", {}).get("rule_fp_count", 0)

    if llm_correct and not rule_correct:
        return (
            "The LLM correctly identified the scenario as "
            f"'{gt_label}' while the rule engine was incorrect. "
            "LLM contextual analysis provided superior accuracy."
        )
    if rule_correct and not llm_correct:
        return (
            "The rule engine correctly identified the scenario as "
            f"'{gt_label}' while the LLM was incorrect. "
            "Rule-based detection was more reliable in this case."
        )
    if llm_correct and rule_correct:
        # Both correct -- check for false positives or added narrative
        if fp_count > 0:
            return (
                f"Both systems reached the correct verdict, but the rule engine "
                f"produced {fp_count} false positive alert(s). The LLM provided "
                f"superior signal-to-noise by avoiding false positives and offering "
                f"a coherent narrative explanation."
            )
        narrative = llm_data.get("narrative", "")
        gaps = llm_data.get("gaps", [])
        extras = []
        if narrative:
            extras.append("a coherent investigative narrative")
        if gaps:
            extras.append(f"{len(gaps)} investigative gap(s) for follow-up")
        if llm_data.get("attack_chain"):
            extras.append("a structured attack chain reconstruction")
        if extras:
            return (
                "Both systems reached the correct verdict. The LLM additionally "
                f"provided {', '.join(extras)}, enriching the investigation."
            )
        return "Both systems reached the correct verdict with comparable coverage."
    return (
        "Both systems produced incorrect verdicts. Manual review is strongly recommended."
    )


def generate_all_reports() -> list[dict]:
    """Generate reports for all scenarios and save to data/reports/."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    scenario_files = sorted((PROJECT_ROOT / "data" / "scenarios").glob("scenario_*.json"))
    scenario_nums = [int(f.stem.split("_")[1]) for f in scenario_files]

    reports = []
    combined_summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "classification": "CONFIDENTIAL",
        "total_scenarios": len(scenario_nums),
        "scenario_summaries": [],
    }

    for num in scenario_nums:
        print(f"\n{'='*60}")
        print(f"  Generating report for Scenario {num}...")
        print(f"{'='*60}")
        report = generate_scenario_report(num)
        reports.append(report)

        # Save individual report
        report_path = REPORTS_DIR / f"scenario_{num}_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  Saved: {report_path}")

        # Add to combined summary
        combined_summary["scenario_summaries"].append({
            "report_id": report["report_id"],
            "scenario_id": report["scenario"]["id"],
            "scenario_name": report["scenario"]["name"],
            "ground_truth": report["scenario"]["ground_truth"],
            "rule_verdict": report["rule_analysis"]["verdict"],
            "llm_verdict": report["llm_analysis"]["verdict"],
            "llm_confidence": report["llm_analysis"]["confidence"],
            "rule_verdict_correct": report["comparative_assessment"]["rule_verdict_correct"],
            "llm_verdict_correct": report["comparative_assessment"]["llm_verdict_correct"],
            "agreement": report["comparative_assessment"]["rule_vs_llm_agreement"],
            "alert_count": report["rule_analysis"]["alert_count"],
            "hallucination_count": report["evidence_integrity"]["hallucination_count"],
            "executive_summary": report["executive_summary"],
        })

    # Overall accuracy
    rule_correct_count = sum(
        1 for s in combined_summary["scenario_summaries"]
        if s["rule_verdict_correct"] is True
    )
    llm_correct_count = sum(
        1 for s in combined_summary["scenario_summaries"]
        if s["llm_verdict_correct"] is True
    )
    combined_summary["overall_accuracy"] = {
        "rule_engine": f"{rule_correct_count}/{len(scenario_nums)}",
        "llm_analysis": f"{llm_correct_count}/{len(scenario_nums)}",
    }

    # Save combined summary
    summary_path = REPORTS_DIR / "combined_summary.json"
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(combined_summary, f, indent=2, ensure_ascii=False)
    print(f"\n  Saved combined summary: {summary_path}")

    return reports


def print_report(report: dict) -> None:
    """Pretty-print a forensic report to stdout in a readable format."""
    divider = "=" * 72
    sub_divider = "-" * 72

    print(f"\n{divider}")
    print(f"  FORENSIC INVESTIGATION REPORT")
    print(f"  Report ID:      {report['report_id']}")
    print(f"  Generated:      {report['generated_at']}")
    print(f"  Classification: {report['classification']}")
    print(f"{divider}")

    # Scenario
    sc = report["scenario"]
    print(f"\n  SCENARIO: {sc['id']} ({sc['name']})")
    print(f"  Ground Truth:   {sc['ground_truth']}")

    # Executive Summary
    print(f"\n{sub_divider}")
    print(f"  EXECUTIVE SUMMARY")
    print(f"{sub_divider}")
    _print_wrapped(report["executive_summary"], indent=4)

    # Timeline Summary
    ts = report["timeline_summary"]
    print(f"\n{sub_divider}")
    print(f"  TIMELINE SUMMARY")
    print(f"{sub_divider}")
    print(f"    Total Events:    {ts['total_events']}")
    print(f"    Time Range:      {ts['time_range']['start']} -> {ts['time_range']['end']}")
    print(f"    Users Involved:  {', '.join(ts['users_involved']) if ts['users_involved'] else 'N/A'}")
    print(f"    Sessions:        {ts['sessions']}")

    # Rule Analysis
    ra = report["rule_analysis"]
    print(f"\n{sub_divider}")
    print(f"  RULE ENGINE ANALYSIS")
    print(f"{sub_divider}")
    print(f"    Verdict:         {ra['verdict']}")
    print(f"    Alert Count:     {ra['alert_count']}")
    print(f"    Rules Triggered: {', '.join(ra['rules_triggered']) if ra['rules_triggered'] else 'None'}")
    print(f"    Severity:        Critical={ra['severity_breakdown']['critical']}, Warning={ra['severity_breakdown']['warning']}")
    if ra["key_findings"]:
        print(f"    Key Findings:")
        for i, finding in enumerate(ra["key_findings"], 1):
            print(f"      {i}. {finding}")

    # LLM Analysis
    la = report["llm_analysis"]
    print(f"\n{sub_divider}")
    print(f"  LLM ANALYSIS")
    print(f"{sub_divider}")
    print(f"    Verdict:         {la['verdict']}")
    print(f"    Confidence:      {la['confidence']}")
    print(f"    Suspect:         {la['suspect'] or 'None identified'}")
    if la["narrative"]:
        print(f"    Narrative:")
        _print_wrapped(la["narrative"], indent=6)
    if la["attack_chain"]:
        print(f"    Attack Chain:")
        for i, step in enumerate(la["attack_chain"], 1):
            if isinstance(step, dict):
                desc = step.get("description", str(step))
                eid = step.get("event_id", "")
                print(f"      {i}. [{eid}] {desc}")
            else:
                print(f"      {i}. {step}")
    if la["evidence_for"]:
        print(f"    Evidence For Attack:  {', '.join(str(e) for e in la['evidence_for'])}")
    if la["evidence_against"]:
        print(f"    Evidence Against:     {', '.join(str(e) for e in la['evidence_against'])}")
    if la["investigative_gaps"]:
        print(f"    Investigative Gaps:")
        for i, gap in enumerate(la["investigative_gaps"], 1):
            print(f"      {i}. {gap}")

    # Comparative Assessment
    ca = report["comparative_assessment"]
    print(f"\n{sub_divider}")
    print(f"  COMPARATIVE ASSESSMENT")
    print(f"{sub_divider}")
    print(f"    Rule vs LLM Agreement: {'Yes' if ca['rule_vs_llm_agreement'] else 'No'}")
    print(f"    Rule Verdict Correct:  {'Yes' if ca['rule_verdict_correct'] else 'No'}")
    print(f"    LLM Verdict Correct:   {'Yes' if ca['llm_verdict_correct'] else 'No'}")
    print(f"    LLM Added Value:")
    _print_wrapped(ca["llm_added_value"], indent=6)

    # Evidence Integrity
    ei = report["evidence_integrity"]
    print(f"\n{sub_divider}")
    print(f"  EVIDENCE INTEGRITY")
    print(f"{sub_divider}")
    print(f"    Hallucination Count:     {ei['hallucination_count']}")
    print(f"    Evidence Grounding:      {ei['evidence_grounding_pct']}%")
    print(f"    Timeline Correct:        {'Yes' if ei['timeline_correct'] else 'No'}")
    print(f"    All References Valid:    {'Yes' if ei['all_references_valid'] else 'No'}")

    # Recommendations
    print(f"\n{sub_divider}")
    print(f"  RECOMMENDATIONS")
    print(f"{sub_divider}")
    for i, rec in enumerate(report["recommendations"], 1):
        print(f"    {i}. {rec}")

    # Appendix summary (not full dump)
    appendix = report.get("appendix", {})
    print(f"\n{sub_divider}")
    print(f"  APPENDIX")
    print(f"{sub_divider}")
    print(f"    Total Events in Appendix: {len(appendix.get('all_events', []))}")
    print(f"    Total Alerts in Appendix: {len(appendix.get('all_alerts', []))}")
    print(f"\n{divider}")
    print(f"  END OF REPORT - {report['report_id']}")
    print(f"{divider}\n")


def _print_wrapped(text: str, indent: int = 4, width: int = 72) -> None:
    """Print text wrapped to a given width with indentation."""
    prefix = " " * indent
    max_line = width - indent
    words = text.split()
    line = prefix
    for word in words:
        if len(line) + len(word) + 1 > width:
            print(line)
            line = prefix + word
        else:
            if line.strip():
                line += " " + word
            else:
                line += word
    if line.strip():
        print(line)


if __name__ == "__main__":
    print("=" * 72)
    print("  FORENSIC FRAMEWORK - Report Generation")
    print("=" * 72)

    all_reports = generate_all_reports()

    for report in all_reports:
        print_report(report)

    print("\nAll reports generated successfully.")
    print(f"Reports saved to: {REPORTS_DIR}")
