#!/usr/bin/env python3
"""Score one or more warrant LLM run directories and verify raw artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_results import load_run_records, summarize_run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_dirs",
        nargs="+",
        type=Path,
        help="Run directories containing records.jsonl.",
    )
    args = parser.parse_args()

    failed = False
    for run_dir in args.run_dirs:
        records_path = run_dir / "records.jsonl"
        summary = summarize_run(load_run_records(records_path))
        output_path = run_dir / "analysis.json"
        output_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        print(f"{run_dir}: {summary['record_count']} records -> {output_path}")
        if not summary["artifact_integrity"]["ok"]:
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
