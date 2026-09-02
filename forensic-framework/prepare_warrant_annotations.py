#!/usr/bin/env python3
"""Create a deterministic blinded annotation package from one LLM run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.evaluation.warrant_annotations import export_annotation_package
from app.evaluation.warrant_results import load_run_records
from app.ingestion.warrant_benchmark import load_cases


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--sample-size", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20_260_902)
    args = parser.parse_args()

    records = load_run_records(args.run_dir / "records.jsonl")
    cases = {case["case_id"]: case for case in load_cases()}
    manifest = export_annotation_package(
        records,
        cases,
        args.output_dir,
        sample_size=args.sample_size,
        seed=args.seed,
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
