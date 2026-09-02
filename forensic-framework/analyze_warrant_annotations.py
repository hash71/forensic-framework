#!/usr/bin/env python3
"""Validate completed warrant annotations and analyze human agreement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_human import analyze_human_annotations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("records_path", type=Path)
    parser.add_argument("annotator_1_csv", type=Path)
    parser.add_argument("annotator_2_csv", type=Path)
    parser.add_argument("adjudication_csv", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    analysis = analyze_human_annotations(
        args.package_dir,
        args.records_path,
        args.annotator_1_csv,
        args.annotator_2_csv,
        args.adjudication_csv,
    )
    payload = json.dumps(analysis, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload)
    print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
