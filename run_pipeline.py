#!/usr/bin/env python3
"""Run the complete forensic analysis pipeline."""

import argparse
import asyncio
import json
import os
import re
import sys
from pathlib import Path

# Ensure project root is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent))

from app.config import setup_logging
setup_logging()


def _detect_mock_mode(cli_mock: bool) -> bool:
    """Determine whether to use mock LLM responses.

    Returns True (mock mode) unless MODAL_ENDPOINT is set to a real value.
    The --mock flag on the CLI defaults to True and can be overridden with
    --no-mock.
    """
    if not cli_mock:
        return False
    endpoint = os.getenv("MODAL_ENDPOINT", "")
    if endpoint and endpoint != "https://your-modal-endpoint.modal.run" and "your-modal" not in endpoint:
        return False
    return True


def run_pipeline(use_mock: bool = True) -> dict:
    """Execute the full forensic analysis pipeline (Phases 1-3).

    Returns a summary dict with counts from each step.
    """
    summary: dict[str, object] = {}

    # ------------------------------------------------------------------
    # Step 1: Generate raw logs from scenario definitions
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 1: Generate raw logs from scenarios ===")
    print("=" * 60)
    try:
        from app.ingestion.log_generator import generate_all

        gen_summary = generate_all()
        scenarios_generated = len(gen_summary)
        total_logs = sum(
            sum(counts.values()) for counts in gen_summary.values()
        )
        print(f"  Scenarios processed: {scenarios_generated}")
        print(f"  Total raw log entries: {total_logs}")
        summary["step1_generate"] = {
            "scenarios": scenarios_generated,
            "total_logs": total_logs,
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step1_generate"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 2: Parse raw logs
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 2: Parse raw logs ===")
    print("=" * 60)
    all_parsed = {}
    try:
        from app.ingestion.parser import parse_all_scenarios

        all_parsed = parse_all_scenarios()
        for snum, parsed in sorted(all_parsed.items()):
            event_count = sum(len(v) for v in parsed.values())
            print(f"  Scenario {snum}: {event_count} parsed events")
        summary["step2_parse"] = {
            "scenarios": len(all_parsed),
            "events_per_scenario": {
                s: sum(len(v) for v in p.values())
                for s, p in all_parsed.items()
            },
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step2_parse"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 3: Normalize events
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 3: Normalize events ===")
    print("=" * 60)
    try:
        from app.normalizer.normalizer import normalize_all

        normalized = normalize_all(all_parsed)
        total_normalized = sum(len(events) for events in normalized.values())
        print(f"  Total normalized events: {total_normalized}")
        summary["step3_normalize"] = {
            "scenarios": len(normalized),
            "total_events": total_normalized,
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step3_normalize"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 4: Build timelines
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 4: Build timelines ===")
    print("=" * 60)
    try:
        from app.timeline.timeline import build_all_timelines

        timelines = build_all_timelines()
        for num in sorted(timelines):
            t = timelines[num]
            tr = t.get("time_range", {})
            print(
                f"  Scenario {num}: {t['total_events']} events, "
                f"{len(t.get('by_user', {}))} users, "
                f"{len(t.get('by_session', {}))} sessions"
            )
            if tr:
                print(f"    Time range: {tr.get('start', '?')} -> {tr.get('end', '?')}")
        summary["step4_timeline"] = {
            "scenarios": len(timelines),
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step4_timeline"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 5: Run correlations
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 5: Run correlations ===")
    print("=" * 60)
    try:
        from app.correlation.correlator import correlate_all

        corr_summary = correlate_all()
        print(f"  Scenarios processed: {corr_summary['scenarios_processed']}")
        for num in sorted(corr_summary["results"]):
            r = corr_summary["results"][num]
            print(f"  Scenario {num}: {r['finding_count']} findings")
            for sev, count in sorted(r.get("severity_summary", {}).items()):
                print(f"    {sev}: {count}")
        summary["step5_correlations"] = {
            "scenarios_processed": corr_summary["scenarios_processed"],
            "total_findings": sum(
                r["finding_count"] for r in corr_summary["results"].values()
            ),
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step5_correlations"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 6: Run rule engine
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 6: Run rule engine ===")
    print("=" * 60)
    try:
        from app.rules.rule_engine import evaluate_all as evaluate_rules

        rule_results = evaluate_rules()
        for key in sorted(rule_results):
            r = rule_results[key]
            print(
                f"  {key}: {r['alert_count']} alerts, "
                f"{r['rules_triggered']} rules fired, "
                f"verdict={r['verdict']}"
            )
        total_alerts = sum(r["alert_count"] for r in rule_results.values())
        summary["step6_rules"] = {
            "scenarios": len(rule_results),
            "total_alerts": total_alerts,
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step6_rules"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 7: Run LLM analysis
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print(f"=== Step 7: Run LLM analysis (mock={use_mock}) ===")
    print("=" * 60)
    llm_results = {}
    try:
        from app.llm.client import analyze_all

        llm_results = asyncio.run(analyze_all(use_mock=use_mock))
        for num in sorted(llm_results):
            r = llm_results[num]
            print(
                f"  Scenario {num}: verdict={r.get('verdict', 'N/A')}, "
                f"confidence={r.get('confidence', 'N/A')}, "
                f"source={r.get('source', 'N/A')}"
            )
        summary["step7_llm"] = {
            "scenarios": len(llm_results),
            "mock": use_mock,
        }
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step7_llm"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Step 8: Run hallucination checks
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Step 8: Run hallucination checks ===")
    print("=" * 60)
    try:
        from app.llm.hallucination_checker import run_hallucination_check

        project_root = Path(__file__).parent
        responses_dir = project_root / "data" / "llm_responses"

        if llm_results:
            # Use in-memory results from step 7
            for num in sorted(llm_results):
                report = run_hallucination_check(llm_results[num], num)
                status = "PASS" if report["hallucination_free"] else "FAIL"
                print(
                    f"  Scenario {num}: {status} "
                    f"(hallucinations={report['hallucination_count']})"
                )
            summary["step8_hallucination"] = {
                "scenarios_checked": len(llm_results),
            }
        elif responses_dir.exists():
            # Fall back to saved response files
            response_files = sorted(responses_dir.glob("scenario_*_response.json"))
            checked = 0
            for rf in response_files:
                match = re.search(r"scenario_(\d+)_response\.json", rf.name)
                if not match:
                    continue
                snum = int(match.group(1))
                with open(rf, "r") as f:
                    resp = json.load(f)
                report = run_hallucination_check(resp, snum)
                status = "PASS" if report["hallucination_free"] else "FAIL"
                print(
                    f"  Scenario {snum}: {status} "
                    f"(hallucinations={report['hallucination_count']})"
                )
                checked += 1
            summary["step8_hallucination"] = {"scenarios_checked": checked}
        else:
            print("  No LLM responses available to check.")
            summary["step8_hallucination"] = {"scenarios_checked": 0}
    except Exception as exc:
        print(f"  ERROR: {exc}")
        summary["step8_hallucination"] = {"error": str(exc)}

    # ------------------------------------------------------------------
    # Final summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("=== Pipeline Complete ===")
    print("=" * 60)
    for step, info in sorted(summary.items()):
        if isinstance(info, dict) and "error" in info:
            print(f"  {step}: ERROR - {info['error']}")
        else:
            print(f"  {step}: {info}")

    if use_mock:
        print("\n  NOTE: LLM results are based on MOCK responses.")

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the complete forensic analysis pipeline (Phases 1-3)."
    )
    parser.add_argument(
        "--mock",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use mock LLM responses (default: True). Use --no-mock to disable.",
    )
    args = parser.parse_args()

    use_mock = _detect_mock_mode(args.mock)
    if use_mock:
        print("Running with MOCK LLM responses.")
    else:
        endpoint = os.getenv("MODAL_ENDPOINT", "")
        print(f"Running with live LLM endpoint: {endpoint}")

    run_pipeline(use_mock=use_mock)
