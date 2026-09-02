#!/usr/bin/env python3
"""Build a blind, post-hoc human-review subset from AI-panel priorities."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_simulated import export_targeted_review_package


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_package", type=Path)
    parser.add_argument("priority_csv", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--limit", type=int, default=120)
    parser.add_argument("--seed", type=int, default=20_260_903)
    args = parser.parse_args()
    manifest = export_targeted_review_package(
        args.source_package,
        args.priority_csv,
        args.output_dir,
        limit=args.limit,
        seed=args.seed,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
