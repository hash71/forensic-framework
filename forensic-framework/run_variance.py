#!/usr/bin/env python3
"""Run-to-run variance probe.

Picks a stratified subset of scenarios (one per family from the holdout
plus all calibration failure cases) and runs each through Gemma N times.
Writes the per-scenario verdict list for downstream Fleiss-kappa and
flip-rate analysis in run_statistics.py.

Output:
    data/variance_runs.json

    [
      {
        "scenario": 16,
        "family": "normal_baseline",
        "label": "BENIGN",
        "runs": ["NO", "NO", "NO", "NO", "NO"]
      },
      ...
    ]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.llm.client import call_modal_llm
from app.llm.prompts import LLM_SYSTEM_PROMPT, build_scenario_prompt


PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
MANIFEST_PATH = DATA_DIR / "corpus_manifest.json"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth" / "ground_truth.json"
OUT_PATH = DATA_DIR / "variance_runs.json"


def _stratified_subset(per_family: int = 2,
                       include_calibration: bool = True) -> list[dict]:
    """Pick a stratified set: `per_family` holdout scenarios per family,
    plus a few calibration scenarios that are known interesting (S14, S15).

    Returns list of dicts: {scenario, family, label}.
    """
    if not MANIFEST_PATH.exists():
        return []
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)
    with open(GROUND_TRUTH_PATH, "r") as f:
        gt = {e["id"]: e for e in json.load(f)["scenarios"]}

    by_family: dict[str, list[dict]] = defaultdict(list)
    for m in manifest["scenarios"]:
        by_family[m["family"]].append(m)

    subset = []
    for family, members in sorted(by_family.items()):
        for m in members[:per_family]:
            n = int(m["scenario_id"].split("_")[1])
            subset.append({
                "scenario": n,
                "family": family,
                "label": m["label"],
            })

    if include_calibration:
        for n in (14, 15):
            subset.append({"scenario": n, "family": "calibration",
                           "label": gt[f"scenario_{n}"]["label"]})

    return subset


async def _run_subset(subset: list[dict], n_runs: int,
                      temperatures: list[float]) -> list[dict]:
    out = []
    grand_start = time.monotonic()
    total_calls = len(subset) * n_runs
    call_idx = 0
    for entry in subset:
        runs = []
        prompt = build_scenario_prompt(entry["scenario"])
        for r in range(n_runs):
            call_idx += 1
            temp = temperatures[r % len(temperatures)]
            t0 = time.monotonic()
            try:
                result = await call_modal_llm(
                    prompt=prompt, system_prompt=LLM_SYSTEM_PROMPT,
                    temperature=temp,
                )
                verdict = result.get("verdict", "?")
            except Exception as exc:
                verdict = "ERR"
                result = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            runs.append(verdict)
            elapsed = time.monotonic() - t0
            print(f"  [{call_idx:3d}/{total_calls}] s{entry['scenario']} "
                  f"run {r + 1}/{n_runs} (T={temp}): "
                  f"{verdict} ({elapsed:.1f}s)", flush=True)
        out.append({
            "scenario": entry["scenario"],
            "family": entry["family"],
            "label": entry["label"],
            "runs": runs,
        })
    print(f"\nvariance run done: "
          f"{time.monotonic() - grand_start:.0f}s wall", flush=True)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-family", type=int, default=2,
                        help="Holdout scenarios sampled per family.")
    parser.add_argument("--n-runs", type=int, default=5,
                        help="Repeated runs per scenario.")
    parser.add_argument("--temperatures", type=str, default="0.1",
                        help="Comma-separated sampling temperatures (rotates "
                             "across runs).")
    args = parser.parse_args()

    temperatures = [float(t) for t in args.temperatures.split(",")]
    subset = _stratified_subset(per_family=args.per_family)
    print(f"variance probe: {len(subset)} scenarios x {args.n_runs} runs = "
          f"{len(subset) * args.n_runs} calls", flush=True)
    out = asyncio.run(_run_subset(subset, args.n_runs, temperatures))
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT_PATH, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Wrote {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
