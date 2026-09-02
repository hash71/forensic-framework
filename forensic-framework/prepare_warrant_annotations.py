#!/usr/bin/env python3
"""Create a deterministic blinded annotation package from one LLM run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from app.evaluation.warrant_annotations import export_annotation_package
from app.evaluation.warrant_results import load_run_records
from app.ingestion.warrant_benchmark import CASES_PATH, PROJECT_ROOT, load_cases


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(PROJECT_ROOT.resolve()))
    except ValueError:
        return path.name


def resolve_cases_path(run_dir: Path, explicit_path: Path | None = None) -> Path:
    """Resolve and authenticate the exact case corpus used by a frozen run."""

    manifest_path = run_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else None
    if explicit_path is not None:
        cases_path = explicit_path.resolve()
    elif manifest and manifest.get("benchmark_path"):
        declared = Path(manifest["benchmark_path"])
        cases_path = declared if declared.is_absolute() else PROJECT_ROOT / declared
    else:
        # Supports auditing a still-running synthetic study, before its final
        # manifest is atomically written. Frozen runs should always use the
        # manifest-declared path above.
        cases_path = CASES_PATH
    if not cases_path.exists():
        raise FileNotFoundError(f"case corpus missing: {cases_path}")
    if manifest and manifest.get("benchmark_sha256"):
        actual = _sha256(cases_path)
        expected = manifest["benchmark_sha256"]
        if actual != expected:
            raise ValueError(
                f"case-corpus hash mismatch: {actual} != {expected}"
            )
    return cases_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument(
        "--cases-path",
        type=Path,
        help=(
            "override the case JSONL path; by default use the frozen run "
            "manifest (or the synthetic corpus for an unfinished run)"
        ),
    )
    parser.add_argument("--sample-size", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20_260_902)
    args = parser.parse_args()

    records_path = args.run_dir / "records.jsonl"
    records = load_run_records(records_path)
    cases_path = resolve_cases_path(args.run_dir, args.cases_path)
    cases = {case["case_id"]: case for case in load_cases(cases_path)}
    manifest = export_annotation_package(
        records,
        cases,
        args.output_dir,
        sample_size=args.sample_size,
        seed=args.seed,
        provenance={
            "source_run_id": records[0]["run_id"] if records else None,
            "source_records_path": _display_path(records_path),
            "source_records_sha256": _sha256(records_path),
            "source_cases_path": _display_path(cases_path),
            "source_cases_sha256": _sha256(cases_path),
        },
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
