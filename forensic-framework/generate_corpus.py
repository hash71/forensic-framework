#!/usr/bin/env python3
"""Generate the 100-scenario holdout corpus (scenarios 16-115).

Reads `config/corpus_spec.yaml` and emits:

  data/scenarios/scenario_{16..115}.json     -- one per scenario
  data/ground_truth/ground_truth.json        -- appended (15 + 100 = 115)
  data/user_baselines.json                   -- appended (4 + 6 = 10 personas)
  data/corpus_manifest.json                  -- generation manifest

Determinism: with a fixed seed the output is byte-identical across runs.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).parent))

from app.ingestion.scenario_factory import (
    FAMILY_GENERATORS,
    build_generated_personas,
    generate_scenario,
    load_spec,
)

PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
SCENARIOS_DIR = DATA_DIR / "scenarios"
GROUND_TRUTH_PATH = DATA_DIR / "ground_truth" / "ground_truth.json"
BASELINES_PATH = DATA_DIR / "user_baselines.json"
MANIFEST_PATH = DATA_DIR / "corpus_manifest.json"


def _load_existing_baselines() -> dict:
    with open(BASELINES_PATH, "r") as f:
        return json.load(f)


def _load_existing_ground_truth() -> dict:
    with open(GROUND_TRUTH_PATH, "r") as f:
        return json.load(f)


def _save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def _flag_calibration_set(gt: dict) -> dict:
    """Flag the original 15 scenarios as calibration (not holdout)."""
    for entry in gt.get("scenarios", []):
        entry.setdefault("holdout", False)
    return gt


def run(seed: int, dry_run: bool = False) -> dict:
    spec = load_spec()
    rng = random.Random(seed)
    spec["seed"] = seed

    # ----- Personas -----
    existing = _load_existing_baselines()
    generated = build_generated_personas(spec)
    combined = {**existing, **generated}

    # ----- Generation -----
    scenarios: list[tuple[dict, dict, dict]] = []
    start_idx = spec["holdout_first_index"]
    total = spec["holdout_count"]

    # Family draw order respects spec counts; each family is filled before
    # the next so generation is auditable family-by-family.
    family_order = list(spec["families"].keys())
    n = start_idx
    for family in family_order:
        for _ in range(spec["families"][family]["count"]):
            # Each scenario gets its own sub-RNG seeded deterministically so
            # one slow family's parameters don't shift downstream scenarios.
            scen_rng = random.Random(rng.randint(0, 2**31 - 1))
            scen, gt_entry, manifest_entry = generate_scenario(
                family, n, scen_rng, combined, spec,
            )
            scenarios.append((scen, gt_entry, manifest_entry))
            n += 1

    if n - start_idx != total:
        raise RuntimeError(
            f"Family counts in spec sum to {n - start_idx}, "
            f"expected {total}."
        )

    if dry_run:
        return {
            "scenarios_planned": len(scenarios),
            "first_id": scenarios[0][0]["scenario_id"],
            "last_id": scenarios[-1][0]["scenario_id"],
        }

    # ----- Write scenario files -----
    SCENARIOS_DIR.mkdir(parents=True, exist_ok=True)
    for scen, _gt, _mf in scenarios:
        path = SCENARIOS_DIR / f"{scen['scenario_id']}.json"
        _save_json(path, scen)

    # ----- Update user baselines (preserves existing 4 unchanged) -----
    _save_json(BASELINES_PATH, combined)

    # ----- Update ground truth (15 calibration + 100 holdout) -----
    gt_doc = _load_existing_ground_truth()
    gt_doc = _flag_calibration_set(gt_doc)
    # Replace any existing holdout entries to keep idempotent
    gt_doc["scenarios"] = [
        e for e in gt_doc["scenarios"] if not e.get("holdout", False)
    ]
    for _scen, gt_entry, _mf in scenarios:
        gt_doc["scenarios"].append(gt_entry)
    _save_json(GROUND_TRUTH_PATH, gt_doc)

    # ----- Manifest -----
    manifest = {
        "seed": seed,
        "spec_path": str(MANIFEST_PATH.parent.parent / "config" /
                          "corpus_spec.yaml"),
        "calibration_count": sum(
            1 for e in gt_doc["scenarios"] if not e.get("holdout")
        ),
        "holdout_count": len(scenarios),
        "scenarios": [m for _s, _g, m in scenarios],
    }
    _save_json(MANIFEST_PATH, manifest)

    # Summary returned to caller for printing
    family_counts: dict[str, int] = {}
    label_counts: dict[str, int] = {"BENIGN": 0, "ATTACK": 0}
    hard_benign = 0
    for _s, gt_entry, m in scenarios:
        family_counts[m["family"]] = family_counts.get(m["family"], 0) + 1
        label_counts[m["label"]] += 1
        if m["hard_benign"]:
            hard_benign += 1
    return {
        "seed": seed,
        "scenarios_written": len(scenarios),
        "first_id": scenarios[0][0]["scenario_id"],
        "last_id": scenarios[-1][0]["scenario_id"],
        "personas_after": len(combined),
        "label_counts": label_counts,
        "family_counts": family_counts,
        "hard_benign": hard_benign,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate the holdout corpus (scenarios 16-115).",
    )
    parser.add_argument("--seed", type=int, default=42,
                        help="Seed for the RNG (default: 42).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute counts but write no files.")
    args = parser.parse_args()

    summary = run(seed=args.seed, dry_run=args.dry_run)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
