#!/usr/bin/env python3
"""Audit frozen confidence/abstention behavior across development and test runs."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from app.evaluation.warrant_results import build_confidence_audit, load_run_records


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("development_run_dir", type=Path)
    parser.add_argument("test_run_dir", type=Path)
    parser.add_argument(
        "--condition",
        default="llm_events_plus_alerts",
        help="shared generator condition whose confidence enters the policy",
    )
    parser.add_argument("--policy-threshold", type=float, default=0.65)
    parser.add_argument(
        "--output",
        type=Path,
        help="default: TEST_RUN_DIR/confidence_audit.json",
    )
    args = parser.parse_args()

    development_path = args.development_run_dir / "records.jsonl"
    test_path = args.test_run_dir / "records.jsonl"
    development_manifest_path = args.development_run_dir / "manifest.json"
    test_manifest_path = args.test_run_dir / "manifest.json"
    audit = build_confidence_audit(
        load_run_records(development_path),
        load_run_records(test_path),
        development_records_sha256=_sha256(development_path),
        test_records_sha256=_sha256(test_path),
        development_manifest=json.loads(development_manifest_path.read_text()),
        test_manifest=json.loads(test_manifest_path.read_text()),
        development_manifest_sha256=_sha256(development_manifest_path),
        test_manifest_sha256=_sha256(test_manifest_path),
        condition=args.condition,
        policy_threshold=args.policy_threshold,
    )
    output = args.output or args.test_run_dir / "confidence_audit.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
