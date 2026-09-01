"""
Evaluation module for the forensic investigation framework.

Computes all evaluation metrics by comparing rule-based and LLM-assisted
results against ground truth across all four scenarios.
"""

import json
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ---------------------------------------------------------------------------
# Data loaders
# ---------------------------------------------------------------------------

def load_ground_truth() -> list[dict]:
    """Load ground truth definitions for all scenarios."""
    gt_path = PROJECT_ROOT / "data" / "ground_truth" / "ground_truth.json"
    with open(gt_path, "r") as f:
        data = json.load(f)
    return data["scenarios"]


def load_rule_results(scenario_num: int) -> dict:
    """Load rule-based detection results for a given scenario."""
    path = PROJECT_ROOT / "data" / "normalized" / f"scenario_{scenario_num}_rule_results.json"
    with open(path, "r") as f:
        return json.load(f)


def load_llm_results(scenario_num: int) -> dict:
    """Load LLM-assisted analysis results for a given scenario."""
    path = PROJECT_ROOT / "data" / "llm_responses" / f"scenario_{scenario_num}_response.json"
    with open(path, "r") as f:
        return json.load(f)


def load_normalized_events(scenario_num: int) -> list[dict]:
    """Load normalized events for a given scenario."""
    path = PROJECT_ROOT / "data" / "normalized" / f"scenario_{scenario_num}_events.json"
    with open(path, "r") as f:
        return json.load(f)


def load_timeline(scenario_num: int) -> dict:
    """Load the timeline data for a given scenario."""
    path = PROJECT_ROOT / "data" / "normalized" / f"scenario_{scenario_num}_timeline.json"
    with open(path, "r") as f:
        return json.load(f)


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse an ISO 8601 timestamp string to a datetime object."""
    # Handle timezone offset format with colon (e.g. +06:00)
    return datetime.fromisoformat(ts_str)


# ---------------------------------------------------------------------------
# Individual evaluation functions
# ---------------------------------------------------------------------------

def evaluate_verdict_accuracy(ground_truth_label: str, rule_verdict: str, llm_verdict: str) -> dict:
    """
    Compare rule-based and LLM verdicts against the ground truth label.

    Mapping:
      Rule: "no_alert" / "suspicious" -> BENIGN, "attack" -> ATTACK
      LLM:  "NO" / "INSUFFICIENT"     -> BENIGN, "YES"   -> ATTACK
    """
    rule_map = {"no_alert": "BENIGN", "suspicious": "BENIGN", "attack": "ATTACK"}
    llm_map = {"NO": "BENIGN", "INSUFFICIENT": "BENIGN", "YES": "ATTACK"}

    rule_mapped = rule_map.get(rule_verdict, "UNKNOWN")
    llm_mapped = llm_map.get(llm_verdict, "UNKNOWN")

    return {
        "ground_truth": ground_truth_label,
        "rule_mapped": rule_mapped,
        "llm_mapped": llm_mapped,
        "rule_correct": rule_mapped == ground_truth_label,
        "llm_correct": llm_mapped == ground_truth_label,
    }


def evaluate_event_recall(ground_truth_steps: list[str], llm_attack_chain: list[dict]) -> dict:
    """
    For ATTACK scenarios, measure how many ground truth attack steps the LLM
    detected.  Uses fuzzy keyword matching between ground truth step names and
    LLM attack chain descriptions.
    """
    if not ground_truth_steps:
        return {
            "total_steps": 0,
            "detected_steps": 0,
            "recall_pct": 100.0,
            "missed_steps": [],
        }

    # Build a single blob of all LLM chain descriptions (lowered) for matching
    chain_text = " ".join(
        step.get("description", "").lower() for step in llm_attack_chain
    )

    # Use the shared keyword map for matching
    keyword_map = ATTACK_STEP_KEYWORD_MAP

    detected: list[str] = []
    missed: list[str] = []

    for step_name in ground_truth_steps:
        keywords = keyword_map.get(step_name, [step_name.replace("_", " ")])
        found = any(kw in chain_text for kw in keywords)
        if found:
            detected.append(step_name)
        else:
            missed.append(step_name)

    total = len(ground_truth_steps)
    detected_count = len(detected)
    recall_pct = round(detected_count / total * 100.0, 2) if total else 100.0

    return {
        "total_steps": total,
        "detected_steps": detected_count,
        "recall_pct": recall_pct,
        "missed_steps": missed,
    }


def evaluate_false_positive_rate(
    ground_truth_label: str,
    rule_alerts: list[dict],
    llm_verdict: str,
    total_events_in_scenario: int = 0,
) -> dict:
    """
    For BENIGN scenarios, count false positive alerts from the rule engine
    and check whether the LLM incorrectly flagged benign activity as an attack.

    Also computes a false_positive_rate_pct relative to total events.
    For ATTACK scenarios the FP rate is still computed (alerts on non-attack
    events) but is less meaningful.
    """
    rule_fp_count = len(rule_alerts) if ground_truth_label == "BENIGN" else 0
    llm_fp = llm_verdict == "YES" if ground_truth_label == "BENIGN" else False

    if total_events_in_scenario > 0:
        fp_rate_pct = round((rule_fp_count / total_events_in_scenario) * 100, 2)
    else:
        fp_rate_pct = 0.0

    return {
        "rule_fp_count": rule_fp_count,
        "llm_fp": llm_fp,
        "false_positive_rate_pct": fp_rate_pct,
    }


def evaluate_llm_quality(hallucination_report: dict) -> dict:
    """
    Summarise LLM quality metrics from a hallucination checker report.

    Takes the output of hallucination_checker.run_hallucination_check().
    """
    hallucination_count = hallucination_report.get("hallucination_count", 0)

    unsupported = hallucination_report.get("unsupported_claims", {})
    evidence_grounding_pct = unsupported.get("evidence_grounding", 100.0)

    timeline = hallucination_report.get("timeline_correctness", {})
    timeline_correct = timeline.get("chronologically_correct", True)

    return {
        "hallucination_count": hallucination_count,
        "evidence_grounding_pct": evidence_grounding_pct,
        "timeline_correct": timeline_correct,
    }


def evaluate_precision(
    ground_truth_steps: list[str],
    rule_alerts: list[dict],
    llm_attack_chain: list[dict],
    keyword_map: dict[str, list[str]],
) -> dict:
    """
    For ATTACK scenarios, compute precision for both rule and LLM detections.

    Rule precision:  fraction of rule alerts that correspond to actual attack
                     steps (true positives).
    LLM precision:   fraction of LLM attack chain steps that reference actual
                     attack events.
    """
    if not ground_truth_steps:
        return {"rule_precision": None, "llm_precision": None}

    # --- Rule precision ---
    total_alerts = len(rule_alerts)
    if total_alerts > 0:
        true_positive_alerts = 0
        for alert in rule_alerts:
            alert_text = alert.get("description", "").lower()
            alert_text += " " + alert.get("rule_name", "").lower()
            for step_name in ground_truth_steps:
                keywords = keyword_map.get(step_name, [step_name.replace("_", " ")])
                if any(kw in alert_text for kw in keywords):
                    true_positive_alerts += 1
                    break
        rule_precision = round(true_positive_alerts / total_alerts, 4)
    else:
        rule_precision = None

    # --- LLM precision ---
    total_chain_steps = len(llm_attack_chain)
    if total_chain_steps > 0:
        valid_chain_steps = 0
        for chain_step in llm_attack_chain:
            step_text = chain_step.get("description", "").lower()
            for step_name in ground_truth_steps:
                keywords = keyword_map.get(step_name, [step_name.replace("_", " ")])
                if any(kw in step_text for kw in keywords):
                    valid_chain_steps += 1
                    break
        llm_precision = round(valid_chain_steps / total_chain_steps, 4)
    else:
        llm_precision = None

    return {
        "rule_precision": rule_precision,
        "llm_precision": llm_precision,
    }


def compute_f1(precision: float | None, recall: float | None) -> float:
    """Compute F1 score from precision and recall (both in 0..1 range)."""
    if precision is not None and recall is not None and (precision + recall) > 0:
        return round(2 * (precision * recall) / (precision + recall), 4)
    return 0.0


def evaluate_time_to_detect(
    ground_truth_steps: list[str],
    rule_alerts: list[dict],
    llm_attack_chain: list[dict],
    timeline_events: list[dict],
    keyword_map: dict[str, list[str]],
) -> dict:
    """
    For ATTACK scenarios, compute how quickly the first attack step was
    detected by rules and the LLM.

    Returns the time delta in seconds between the first actual attack event
    and the first detection alert / chain reference.
    """
    if not ground_truth_steps or not timeline_events:
        return {"rule_seconds": None, "llm_seconds": None}

    # Build set of event IDs that are part of attack steps via keyword matching
    attack_event_ids: set[str] = set()
    for evt in timeline_events:
        evt_text = (
            evt.get("action", "").lower() + " "
            + (evt.get("resource", "") or "").lower() + " "
            + evt.get("status", "").lower()
        )
        for step_name in ground_truth_steps:
            keywords = keyword_map.get(step_name, [step_name.replace("_", " ")])
            if any(kw in evt_text for kw in keywords):
                attack_event_ids.add(evt.get("event_id"))
                break

    # Find first attack event timestamp
    first_attack_time = None
    for evt in timeline_events:
        if evt.get("event_id") in attack_event_ids:
            first_attack_time = _parse_timestamp(evt["timestamp"])
            break  # timeline is sorted

    if first_attack_time is None:
        # Fallback: use the first event in the timeline as approximation
        # if keyword matching did not identify specific attack events
        first_attack_time = _parse_timestamp(timeline_events[0]["timestamp"])

    # --- Rule time-to-detect ---
    rule_seconds = None
    if rule_alerts:
        first_alert_time = _parse_timestamp(rule_alerts[0]["timestamp"])
        for alert in rule_alerts[1:]:
            t = _parse_timestamp(alert["timestamp"])
            if t < first_alert_time:
                first_alert_time = t
        delta = (first_alert_time - first_attack_time).total_seconds()
        rule_seconds = round(delta, 2)

    # --- LLM time-to-detect ---
    llm_seconds = None
    if llm_attack_chain:
        # Build event_id -> timestamp lookup from timeline
        event_ts_map: dict[str, datetime] = {}
        for evt in timeline_events:
            event_ts_map[evt["event_id"]] = _parse_timestamp(evt["timestamp"])

        first_chain_event_time = None
        for chain_step in llm_attack_chain:
            eid = chain_step.get("event_id")
            if eid and eid in event_ts_map:
                t = event_ts_map[eid]
                if first_chain_event_time is None or t < first_chain_event_time:
                    first_chain_event_time = t

        if first_chain_event_time is not None:
            delta = (first_chain_event_time - first_attack_time).total_seconds()
            llm_seconds = round(delta, 2)

    return {"rule_seconds": rule_seconds, "llm_seconds": llm_seconds}


def evaluate_rule_breakdown(
    ground_truth_steps: list[str],
    rule_alerts: list[dict],
    keyword_map: dict[str, list[str]],
) -> dict:
    """
    Build a per-rule breakdown showing which rules triggered and whether
    they contributed to detecting actual attack steps.
    """
    breakdown: dict[str, dict] = {}

    for alert in rule_alerts:
        rid = alert.get("rule_id", "UNKNOWN")
        if rid not in breakdown:
            breakdown[rid] = {
                "triggered": True,
                "alert_count": 0,
                "contributed_to_detection": False,
            }
        breakdown[rid]["alert_count"] += 1

        # Check if this alert relates to any attack step
        if ground_truth_steps:
            alert_text = alert.get("description", "").lower()
            alert_text += " " + alert.get("rule_name", "").lower()
            for step_name in ground_truth_steps:
                keywords = keyword_map.get(step_name, [step_name.replace("_", " ")])
                if any(kw in alert_text for kw in keywords):
                    breakdown[rid]["contributed_to_detection"] = True
                    break

    return breakdown


# ---------------------------------------------------------------------------
# Shared keyword map for matching ground truth steps
# ---------------------------------------------------------------------------

ATTACK_STEP_KEYWORD_MAP: dict[str, list[str]] = {
    "failed_login_attempts": ["failed login", "failed auth", "brute"],
    "login_unusual_ip": ["unusual ip", "tor", "login", "successful login", "initial access"],
    "privilege_escalation": ["privilege", "escalat"],
    "bulk_file_download": ["bulk", "download", "exfiltrat"],
    "log_deletion": ["log delet", "log removal", "anti-forensic", "deleted"],
    "logout": ["logout", "logged out", "session end"],
    "login_normal": ["login", "logged in", "authentication"],
    "minor_privilege_change": ["privilege", "role", "permission"],
    "slow_scope_expansion_day1": ["scope", "expansion", "day 1", "day1", "additional"],
    "slow_scope_expansion_day2": ["scope", "expansion", "day 2", "day2", "continued", "further"],
    "systematic_download_day3": ["download", "systematic", "day 3", "day3", "exfiltrat"],
    "data_exfiltration_complete": ["exfiltrat", "complete", "final", "transfer"],
    "session_hijack_ip_change": ["hijack", "ip change", "session", "unusual ip"],
    "unauthorized_hr_access_1": ["unauthorized", "hr", "access"],
    "unauthorized_hr_access_2": ["unauthorized", "hr", "access"],
    "unauthorized_hr_access_3": ["unauthorized", "hr", "access"],
}


# ---------------------------------------------------------------------------
# Composite evaluators
# ---------------------------------------------------------------------------

def evaluate_scenario(scenario_num: int) -> dict:
    """
    Run the full evaluation suite for a single scenario.

    Loads all relevant data, runs every evaluation function, and returns
    a comprehensive results dictionary.
    """
    from app.llm.hallucination_checker import run_hallucination_check

    # Load data
    ground_truths = load_ground_truth()
    gt = ground_truths[scenario_num - 1]  # scenarios are 1-indexed

    rule_results = load_rule_results(scenario_num)
    llm_results = load_llm_results(scenario_num)
    normalized_events = load_normalized_events(scenario_num)
    timeline_data = load_timeline(scenario_num)
    timeline_events = timeline_data.get("timeline", [])

    total_events_in_scenario = len(normalized_events)

    # Determine source
    is_mock = llm_results.get("source", "").upper() == "MOCK"

    rule_alerts = rule_results.get("alerts", [])
    llm_attack_chain = llm_results.get("attack_chain", [])
    attack_steps = gt.get("attack_steps", [])

    # Verdict accuracy
    verdict_eval = evaluate_verdict_accuracy(
        gt["label"],
        rule_results["verdict"],
        llm_results["verdict"],
    )

    # Event recall (ATTACK scenarios only)
    if gt["label"] == "ATTACK":
        recall_eval = evaluate_event_recall(
            attack_steps,
            llm_attack_chain,
        )
    else:
        recall_eval = {
            "total_steps": 0,
            "detected_steps": 0,
            "recall_pct": None,
            "missed_steps": [],
        }

    # False positive rate
    fp_eval = evaluate_false_positive_rate(
        gt["label"],
        rule_alerts,
        llm_results["verdict"],
        total_events_in_scenario,
    )

    # Precision (ATTACK scenarios only)
    if gt["label"] == "ATTACK":
        precision_eval = evaluate_precision(
            attack_steps,
            rule_alerts,
            llm_attack_chain,
            ATTACK_STEP_KEYWORD_MAP,
        )
    else:
        precision_eval = {"rule_precision": None, "llm_precision": None}

    # F1 Score
    rule_recall_frac = (recall_eval["recall_pct"] / 100.0) if recall_eval["recall_pct"] is not None else None
    # For rule recall, use alert-based detection of attack steps as a proxy
    # (same logic as LLM recall but applied to rule alerts)
    if gt["label"] == "ATTACK" and attack_steps:
        alert_text_blob = " ".join(
            (a.get("description", "") + " " + a.get("rule_name", "")).lower()
            for a in rule_alerts
        )
        rule_detected = sum(
            1 for step in attack_steps
            if any(
                kw in alert_text_blob
                for kw in ATTACK_STEP_KEYWORD_MAP.get(step, [step.replace("_", " ")])
            )
        )
        rule_recall_frac = rule_detected / len(attack_steps) if attack_steps else None

    f1_eval = {
        "rule_f1": compute_f1(precision_eval["rule_precision"], rule_recall_frac),
        "llm_f1": compute_f1(
            precision_eval["llm_precision"],
            (recall_eval["recall_pct"] / 100.0) if recall_eval["recall_pct"] is not None else None,
        ),
    }

    # Time-to-detect (ATTACK scenarios only)
    if gt["label"] == "ATTACK":
        ttd_eval = evaluate_time_to_detect(
            attack_steps,
            rule_alerts,
            llm_attack_chain,
            timeline_events,
            ATTACK_STEP_KEYWORD_MAP,
        )
    else:
        ttd_eval = {"rule_seconds": None, "llm_seconds": None}

    # Rule breakdown
    rule_breakdown = evaluate_rule_breakdown(
        attack_steps,
        rule_alerts,
        ATTACK_STEP_KEYWORD_MAP,
    )

    # Hallucination / LLM quality
    hallucination_report = run_hallucination_check(llm_results, scenario_num)
    quality_eval = evaluate_llm_quality(hallucination_report)

    return {
        "scenario": scenario_num,
        "scenario_name": gt.get("name", f"scenario_{scenario_num}"),
        "ground_truth_label": gt["label"],
        "rule_verdict": rule_results["verdict"],
        "llm_verdict": llm_results["verdict"],
        "llm_confidence": llm_results.get("confidence", "N/A"),
        "is_mock": is_mock,
        "verdict_accuracy": verdict_eval,
        "event_recall": recall_eval,
        "false_positives": fp_eval,
        "precision": precision_eval,
        "f1": f1_eval,
        "time_to_detect": ttd_eval,
        "rule_breakdown": rule_breakdown,
        "llm_quality": quality_eval,
        "hallucination_report": hallucination_report,
    }


def evaluate_all() -> list[dict]:
    """
    Evaluate all scenarios and persist the results to
    data/evaluation_results.json.
    """
    scenario_files = sorted((PROJECT_ROOT / "data" / "scenarios").glob("scenario_*.json"))
    scenario_nums = [int(f.stem.split("_")[1]) for f in scenario_files]

    results = []
    for scenario_num in scenario_nums:
        result = evaluate_scenario(scenario_num)
        results.append(result)

    output_path = PROJECT_ROOT / "data" / "evaluation_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Evaluation results saved to {output_path}")
    return results


# ---------------------------------------------------------------------------
# Pretty-print comparison table
# ---------------------------------------------------------------------------

def print_comparison_table(results: list[dict]) -> None:
    """Print a formatted comparison table of all scenario evaluation results."""
    header = (
        f"{'Scenario':<20} "
        f"{'GT':<8} "
        f"{'Rule Verd.':<14} "
        f"{'LLM Verd.':<14} "
        f"{'Recall':<14} "
        f"{'R-Prec':<8} "
        f"{'L-Prec':<8} "
        f"{'R-F1':<7} "
        f"{'L-F1':<7} "
        f"{'FP%':<7} "
        f"{'R-FP':<6} "
        f"{'L-FP':<6} "
        f"{'R-TTD':<8} "
        f"{'L-TTD':<8} "
        f"{'Halluc':<8} "
        f"{'Src':<6} "
        f"{'Notes'}"
    )

    separator = "-" * len(header)

    print()
    print(separator)
    print(header)
    print(separator)

    for r in results:
        scenario_name = r["scenario_name"]
        gt_label = r["ground_truth_label"]

        # Verdict columns with correctness indicator
        rule_correct = r["verdict_accuracy"]["rule_correct"]
        llm_correct = r["verdict_accuracy"]["llm_correct"]
        rule_str = f"{r['rule_verdict']}" + (" [OK]" if rule_correct else " [X]")
        llm_str = f"{r['llm_verdict']}" + (" [OK]" if llm_correct else " [X]")

        # Event recall
        recall = r["event_recall"]
        if recall["recall_pct"] is not None:
            recall_str = f"{recall['recall_pct']:.0f}% ({recall['detected_steps']}/{recall['total_steps']})"
        else:
            recall_str = "N/A"

        # Precision
        prec = r.get("precision", {})
        r_prec_str = f"{prec['rule_precision']:.2f}" if prec.get("rule_precision") is not None else "N/A"
        l_prec_str = f"{prec['llm_precision']:.2f}" if prec.get("llm_precision") is not None else "N/A"

        # F1
        f1 = r.get("f1", {})
        r_f1_str = f"{f1.get('rule_f1', 0):.2f}" if f1.get("rule_f1") is not None else "N/A"
        l_f1_str = f"{f1.get('llm_f1', 0):.2f}" if f1.get("llm_f1") is not None else "N/A"

        # False positives
        fp = r["false_positives"]
        fp_rate_str = f"{fp.get('false_positive_rate_pct', 0):.1f}%"
        rule_fp_str = str(fp["rule_fp_count"])
        llm_fp_str = "YES" if fp["llm_fp"] else "NO"

        # Time-to-detect
        ttd = r.get("time_to_detect", {})
        r_ttd_str = f"{ttd['rule_seconds']:.0f}s" if ttd.get("rule_seconds") is not None else "N/A"
        l_ttd_str = f"{ttd['llm_seconds']:.0f}s" if ttd.get("llm_seconds") is not None else "N/A"

        # LLM quality
        quality = r["llm_quality"]
        halluc_str = str(quality["hallucination_count"])

        # Source
        source_str = "MOCK" if r["is_mock"] else "LIVE"

        # Notes
        notes_parts: list[str] = []
        if r["is_mock"]:
            notes_parts.append("Mock")
        if not rule_correct:
            notes_parts.append("Rule wrong")
        if not llm_correct:
            notes_parts.append("LLM wrong")
        if recall["missed_steps"]:
            notes_parts.append(f"Missed: {', '.join(recall['missed_steps'])}")
        if not quality["timeline_correct"]:
            notes_parts.append("Timeline err")
        notes_str = "; ".join(notes_parts) if notes_parts else "-"

        row = (
            f"{scenario_name:<20} "
            f"{gt_label:<8} "
            f"{rule_str:<14} "
            f"{llm_str:<14} "
            f"{recall_str:<14} "
            f"{r_prec_str:<8} "
            f"{l_prec_str:<8} "
            f"{r_f1_str:<7} "
            f"{l_f1_str:<7} "
            f"{fp_rate_str:<7} "
            f"{rule_fp_str:<6} "
            f"{llm_fp_str:<6} "
            f"{r_ttd_str:<8} "
            f"{l_ttd_str:<8} "
            f"{halluc_str:<8} "
            f"{source_str:<6} "
            f"{notes_str}"
        )
        print(row)

    print(separator)
    print()


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    results = evaluate_all()
    print_comparison_table(results)
