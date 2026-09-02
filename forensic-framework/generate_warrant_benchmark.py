#!/usr/bin/env python3
"""Generate and validate the paired forensic-warrant benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.ingestion.warrant_benchmark import (
    generate_cases,
    validate_cases,
    write_benchmark,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(__file__).parent / "data" / "warrant_benchmark",
    )
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()

    cases = generate_cases()
    validate_cases(cases)
    if args.check_only:
        summary = {
            "base_cases": len({case["base_case_id"] for case in cases}),
            "case_variants": len(cases),
            "status": "valid",
        }
    else:
        summary = write_benchmark(cases, args.output_dir)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

