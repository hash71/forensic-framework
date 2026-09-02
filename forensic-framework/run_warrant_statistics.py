#!/usr/bin/env python3
"""Run the frozen cluster-aware statistical analysis for one warrant run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_results import load_run_records
from app.evaluation.warrant_stats import build_statistical_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--bootstrap-resamples", type=int, default=10_000)
    args = parser.parse_args()

    records = load_run_records(args.run_dir / "records.jsonl")
    report = build_statistical_report(
        records,
        bootstrap_resamples=args.bootstrap_resamples,
    )
    output_path = args.run_dir / "statistics.json"
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
