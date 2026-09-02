#!/usr/bin/env python3
"""Analyze a complete AI-reviewer simulation without calling it expert truth."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_simulated import (
    analyze_simulated_panel,
    write_priority_csv,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("records_path", type=Path)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--priority-limit", type=int, default=120)
    args = parser.parse_args()
    analysis, priority = analyze_simulated_panel(
        args.package_dir,
        args.records_path,
        args.run_dir,
        priority_limit=args.priority_limit,
    )
    analysis_path = args.run_dir / "analysis.json"
    priority_path = args.run_dir / "priority_for_human_review.csv"
    analysis_path.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n")
    write_priority_csv(priority_path, priority)
    print(analysis_path)
    print(priority_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
