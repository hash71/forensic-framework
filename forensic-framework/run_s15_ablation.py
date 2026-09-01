"""
S15 no-rule-context ablation runner.

Re-runs scenario 15 (end_of_quarter_legitimate_bulk) under two conditions:
  - rule_context     : LLM receives baselines + timeline + rule alerts (paper headline)
  - no_rule_context  : LLM receives baselines + timeline only (rule alerts omitted)

Saves both responses with the metadata schema specified for the paper claim:

    scenario_id, condition, model_output_raw, parsed_verdict, parsed_suspect,
    validator_result, timestamp, model_name, temperature, prompt_version, commit_hash

Outputs are written to data/ablation/S15_<condition>.json.

Usage:
    # Requires the live LLM endpoint (Modal or local vLLM/Ollama) configured in .env
    python3 run_s15_ablation.py
    python3 run_s15_ablation.py --runs 5     # for statistical mean +/- std

The two saved files are the evidence artefacts that promote the S15 ablation
claim from "future work" to "measured result" in the paper.
"""
from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import os
import subprocess
from pathlib import Path

from app.llm.client import call_modal_llm  # noqa: E402  (relative to project root)
from app.llm.prompts import LLM_SYSTEM_PROMPT, build_analysis_prompt  # noqa: E402
from app.llm.hallucination_checker import run_hallucination_check  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent
SCENARIO_ID = 15
SCENARIO_NUM = 15
PROMPT_VERSION = "v1.0"  # bump if app/llm/prompts.py changes
DEFAULT_TEMPERATURE = 0.1
DEFAULT_MODEL = os.environ.get("MODAL_MODEL", "fusion-gemma")


def _load_inputs() -> tuple[dict, list, list]:
    """Load baselines, timeline, and rule alerts for S15 from saved artefacts."""
    base = PROJECT_ROOT / "data"
    with open(base / "user_baselines.json", "r") as f:
        baselines = json.load(f)
    with open(base / "normalized" / f"scenario_{SCENARIO_NUM}_timeline.json", "r") as f:
        timeline_data = json.load(f)
    timeline = timeline_data.get("timeline", []) if isinstance(timeline_data, dict) else timeline_data
    with open(base / "normalized" / f"scenario_{SCENARIO_NUM}_rule_results.json", "r") as f:
        rule_results = json.load(f)
    rule_alerts = rule_results.get("alerts", [])
    return baselines, timeline, rule_alerts


def _git_commit_hash() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=PROJECT_ROOT, text=True
        ).strip()[:7]
    except Exception:
        return "unknown"


def _parse_verdict(resp: dict) -> str:
    return str(resp.get("verdict", "UNKNOWN"))


def _parse_suspect(resp: dict) -> str | None:
    return resp.get("suspect")


def run_one(condition: str, temperature: float = DEFAULT_TEMPERATURE) -> dict:
    """Run S15 once under the given condition and return the full record."""
    assert condition in ("rule_context", "no_rule_context")
    baselines, timeline, rule_alerts = _load_inputs()

    # The no-rule-context condition simply replaces the alerts list with [].
    alerts_for_prompt = rule_alerts if condition == "rule_context" else []

    prompt = build_analysis_prompt(
        baselines=baselines,
        timeline=timeline,
        triggered_rules=alerts_for_prompt,
        scenario_id=f"scenario_{SCENARIO_NUM}",
    )

    raw = asyncio.run(
        call_modal_llm(prompt=prompt, system_prompt=LLM_SYSTEM_PROMPT, temperature=temperature)
    )
    # call_modal_llm returns the parsed JSON dict (per app/llm/client.py behaviour).
    parsed = raw if isinstance(raw, dict) else json.loads(raw)
    validator = run_hallucination_check(parsed, SCENARIO_NUM)

    record = {
        "scenario_id": f"S{SCENARIO_ID}",
        "condition": condition,
        "model_output_raw": parsed,
        "parsed_verdict": _parse_verdict(parsed),
        "parsed_suspect": _parse_suspect(parsed),
        "validator_result": validator,
        "timestamp": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "model_name": DEFAULT_MODEL,
        "temperature": temperature,
        "prompt_version": PROMPT_VERSION,
        "commit_hash": _git_commit_hash(),
    }
    return record


def main() -> None:
    parser = argparse.ArgumentParser(description="Run S15 no-rule-context ablation.")
    parser.add_argument("--runs", type=int, default=1, help="Number of repeated runs per condition (for mean/std).")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    args = parser.parse_args()

    out_dir = PROJECT_ROOT / "data" / "ablation"
    out_dir.mkdir(parents=True, exist_ok=True)

    summary: list[dict] = []
    for condition in ("rule_context", "no_rule_context"):
        per_run = []
        for run_idx in range(args.runs):
            print(f"--- Running S15 / {condition} / run {run_idx + 1} of {args.runs} ---")
            record = run_one(condition, temperature=args.temperature)
            per_run.append(record)
            run_path = out_dir / f"S15_{condition}_run{run_idx + 1}.json"
            with open(run_path, "w") as f:
                json.dump(record, f, indent=2)
            print(f"  verdict={record['parsed_verdict']!r}  suspect={record['parsed_suspect']!r}  saved -> {run_path.name}")

        # Save the canonical (single) artefact at the path expected by the paper claim.
        canonical_path = out_dir / f"S15_{condition}.json"
        with open(canonical_path, "w") as f:
            json.dump(per_run[0], f, indent=2)

        verdicts = [r["parsed_verdict"] for r in per_run]
        summary.append({
            "condition": condition,
            "runs": args.runs,
            "verdicts": verdicts,
            "majority_verdict": max(set(verdicts), key=verdicts.count),
        })

    summary_path = out_dir / "S15_ablation_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print()
    print("=== S15 ablation summary ===")
    for row in summary:
        print(row)
    print()
    print(f"Canonical artefacts:")
    print(f"  {out_dir / 'S15_rule_context.json'}")
    print(f"  {out_dir / 'S15_no_rule_context.json'}")
    print(f"Summary: {summary_path}")
    print()
    print("If the no_rule_context verdict differs from the rule_context verdict,")
    print("update the paper to claim the measured reversal. Otherwise, soften the")
    print("rule-context-amplification narrative accordingly.")


if __name__ == "__main__":
    main()
