#!/usr/bin/env python3
"""Extended rule-context ablation.

S15 demonstrated that rule alerts in the LLM prompt can amplify false
positives. This script tests whether that pattern generalizes by running
rule-context vs no-rule-context, N=5 each, on every hard_benign scenario
and every decoy_misdirection scenario in the corpus.

Output:
    data/ablation/extended_summary.json
    data/ablation/extended/<scenario>_<condition>_run<k>.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.llm.client import call_modal_llm
from app.llm.prompts import LLM_SYSTEM_PROMPT, build_analysis_prompt


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
NORMALIZED_DIR = DATA_DIR / "normalized"
MANIFEST_PATH = DATA_DIR / "corpus_manifest.json"
BASELINES_PATH = DATA_DIR / "user_baselines.json"
OUT_DIR = DATA_DIR / "ablation" / "extended"
SUMMARY_PATH = DATA_DIR / "ablation" / "extended_summary.json"


def _scenarios_to_ablate() -> list[dict]:
    """Pick targets: hard_benign + decoy_misdirection families."""
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)
    chosen = []
    for m in manifest["scenarios"]:
        if m["hard_benign"] or m["family"] == "decoy_misdirection":
            chosen.append({
                "scenario": int(m["scenario_id"].split("_")[1]),
                "family": m["family"],
                "label": m["label"],
                "hard_benign": m["hard_benign"],
            })
    return chosen


def _load_inputs(scenario_num: int) -> tuple[dict, list, list]:
    with open(BASELINES_PATH, "r") as f:
        baselines = json.load(f)
    with open(NORMALIZED_DIR / f"scenario_{scenario_num}_timeline.json", "r") as f:
        timeline_data = json.load(f)
    timeline = (timeline_data.get("timeline", [])
                 if isinstance(timeline_data, dict) else timeline_data)
    with open(NORMALIZED_DIR / f"scenario_{scenario_num}_rule_results.json", "r") as f:
        rule_data = json.load(f)
    alerts = rule_data.get("alerts", [])
    return baselines, timeline, alerts


async def _run_one(scenario_num: int, condition: str, run_idx: int,
                    baselines: dict, timeline: list, alerts: list) -> dict:
    """Run one scenario × condition × run. Returns the record dict."""
    if condition == "no_rule_context":
        rule_alerts = []
    else:
        rule_alerts = alerts
    prompt = build_analysis_prompt(
        baselines=baselines, timeline=timeline,
        triggered_rules=rule_alerts,
        scenario_id=f"scenario_{scenario_num}",
    )
    t0 = time.monotonic()
    try:
        result = await call_modal_llm(
            prompt=prompt, system_prompt=LLM_SYSTEM_PROMPT,
        )
        err = None
    except Exception as exc:
        result = {}
        err = f"{type(exc).__name__}: {str(exc)[:200]}"
    elapsed = time.monotonic() - t0
    record = {
        "scenario": scenario_num,
        "condition": condition,
        "run_idx": run_idx,
        "verdict": result.get("verdict"),
        "suspect": result.get("suspect"),
        "confidence": result.get("confidence"),
        "elapsed_s": elapsed,
        "error": err,
        "n_alerts_in_prompt": len(rule_alerts),
    }
    return record


async def _main_async(args) -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    targets = _scenarios_to_ablate()
    if args.limit:
        targets = targets[: args.limit]
    print(f"extended ablation: {len(targets)} scenarios x 2 conditions x "
          f"{args.n_runs} runs = {len(targets) * 2 * args.n_runs} calls",
          flush=True)
    conditions = ["rule_context", "no_rule_context"]
    summary_rows: list[dict] = []
    grand_start = time.monotonic()
    call_idx = 0
    total = len(targets) * 2 * args.n_runs

    for tgt in targets:
        scen = tgt["scenario"]
        baselines, timeline, alerts = _load_inputs(scen)
        for cond in conditions:
            verdicts = []
            for k in range(args.n_runs):
                call_idx += 1
                rec = await _run_one(
                    scen, cond, k, baselines, timeline, alerts,
                )
                rec_path = OUT_DIR / f"scenario_{scen}_{cond}_run{k + 1}.json"
                with open(rec_path, "w") as f:
                    json.dump(rec, f, indent=2)
                verdicts.append(rec["verdict"] or "ERR")
                print(f"  [{call_idx:3d}/{total}] s{scen} ({tgt['family']}) "
                      f"{cond} run{k + 1}: {rec['verdict']} "
                      f"({rec['elapsed_s']:.1f}s)", flush=True)
            counter = Counter(verdicts)
            majority = counter.most_common(1)[0][0]
            summary_rows.append({
                "scenario": scen,
                "family": tgt["family"],
                "label": tgt["label"],
                "hard_benign": tgt["hard_benign"],
                "condition": cond,
                "verdicts": verdicts,
                "majority": majority,
                "n_alerts_in_prompt": rec["n_alerts_in_prompt"],
            })

    # Per-scenario reversal flag
    by_scenario: dict[int, dict] = {}
    for row in summary_rows:
        by_scenario.setdefault(row["scenario"], {"family": row["family"],
                                                 "label": row["label"]})
        by_scenario[row["scenario"]][row["condition"]] = row

    reversals = []
    for scen, blob in by_scenario.items():
        rc = blob.get("rule_context", {}).get("majority")
        nrc = blob.get("no_rule_context", {}).get("majority")
        if rc != nrc:
            reversals.append({
                "scenario": scen, "family": blob["family"],
                "label": blob["label"],
                "rule_context": rc, "no_rule_context": nrc,
            })

    summary = {
        "n_scenarios": len(targets),
        "n_runs_per_condition": args.n_runs,
        "wall_seconds": time.monotonic() - grand_start,
        "model": "fusion-gemma",
        "rows": summary_rows,
        "verdict_reversals": reversals,
        "n_reversals": len(reversals),
    }
    with open(SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nReversals: {len(reversals)} / {len(targets)}", flush=True)
    print(f"Wrote {SUMMARY_PATH}", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n-runs", type=int, default=5)
    parser.add_argument("--limit", type=int, default=0,
                        help="Limit number of scenarios (0 = all).")
    args = parser.parse_args()
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    sys.exit(main())
