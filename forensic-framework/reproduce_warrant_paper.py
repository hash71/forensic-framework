#!/usr/bin/env python3
"""Verify frozen runs and regenerate the warrant paper's analysis artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
MONOREPO_ROOT = PROJECT_ROOT.parent
PAPER_DIR = MONOREPO_ROOT / "conference_paper"


def _run(*args: str, cwd: Path) -> None:
    print("+", " ".join(args), flush=True)
    subprocess.run(args, cwd=cwd, check=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def ensure_paper_build_dir() -> Path:
    """Create the ignored Tectonic output directory in a fresh artifact."""

    build_dir = PAPER_DIR / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    return build_dir


def verify_complete_run(
    run_dir: Path,
    *,
    allow_manifest_only_benchmark: bool = False,
) -> dict:
    """Reject incomplete, duplicated, or benchmark-mismatched frozen runs."""

    manifest_path = run_dir / "manifest.json"
    records_path = run_dir / "records.jsonl"
    if not manifest_path.exists() or not records_path.exists():
        raise FileNotFoundError(f"{run_dir} lacks manifest.json or records.jsonl")
    manifest = json.loads(manifest_path.read_text())
    records = _load_records(records_path)
    keys = {
        (record["case_id"], record["condition"], record["repetition"])
        for record in records
    }
    expected = (
        int(manifest["case_count"])
        * len(manifest["conditions"])
        * int(manifest["repetitions"])
    )
    if len(records) != expected or len(keys) != expected:
        raise ValueError(
            f"{run_dir}: expected {expected} unique records, found "
            f"{len(records)} records and {len(keys)} unique keys"
        )
    case_ids = sorted({record["case_id"] for record in records})
    actual_case_ids_sha256 = hashlib.sha256("\n".join(case_ids).encode()).hexdigest()
    expected_case_ids_sha256 = manifest.get("case_ids_sha256")
    if (
        expected_case_ids_sha256 is not None
        and actual_case_ids_sha256 != expected_case_ids_sha256
    ):
        raise ValueError(
            f"case-ID hash mismatch: {actual_case_ids_sha256} != "
            f"{expected_case_ids_sha256}"
        )
    benchmark_value = manifest.get("benchmark_sha256")
    benchmark_relative = manifest.get("benchmark_path")
    if benchmark_relative is None:
        if not allow_manifest_only_benchmark:
            raise ValueError(f"{run_dir}: manifest lacks benchmark_path")
        if not isinstance(benchmark_value, str) or len(benchmark_value) != 64:
            raise ValueError(f"{run_dir}: invalid manifest-only benchmark hash")
        actual_benchmark = benchmark_value
        benchmark_verification = "manifest_only_historical_source_not_packaged"
    else:
        benchmark_path = PROJECT_ROOT / benchmark_relative
        if not benchmark_path.exists():
            raise FileNotFoundError(f"manifest benchmark missing: {benchmark_path}")
        actual_benchmark = _sha256(benchmark_path)
        if actual_benchmark != benchmark_value:
            raise ValueError(
                f"benchmark hash mismatch: {actual_benchmark} != {benchmark_value}"
            )
        benchmark_verification = "packaged_file_hash_verified"
    run_ids = {record["run_id"] for record in records}
    if run_ids != {manifest["run_id"]}:
        raise ValueError(f"run-id mismatch: records={run_ids}, manifest={manifest['run_id']}")
    records_sha256 = _sha256(records_path)
    release_path = run_dir / "release_redactions.json"
    release_verified = False
    if release_path.exists():
        release = json.loads(release_path.read_text())
        expected_records_sha256 = release.get("post_redaction_records_sha256")
        if expected_records_sha256 != records_sha256:
            raise ValueError(
                f"release-record hash mismatch: {records_sha256} != "
                f"{expected_records_sha256}"
            )
        if release.get("run_id") != manifest["run_id"]:
            raise ValueError("release-redaction run ID does not match run manifest")
        release_verified = True
    return {
        "run_id": manifest["run_id"],
        "record_count": len(records),
        "records_sha256": records_sha256,
        "release_records_sha256_verified": release_verified,
        "benchmark_sha256": actual_benchmark,
        "benchmark_sha256_verification": benchmark_verification,
        "case_ids_sha256": actual_case_ids_sha256,
        "git_commit": manifest.get("git_commit"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path, help="complete synthetic warrant run")
    parser.add_argument(
        "--development-run-dir",
        type=Path,
        help=(
            "disjoint development run used only to audit whether confidence "
            "calibration was supportable"
        ),
    )
    parser.add_argument("--external-run-dir", type=Path)
    parser.add_argument("--human-analysis", type=Path)
    parser.add_argument("--simulated-analysis", type=Path)
    parser.add_argument("--bootstrap-resamples", type=int, default=10_000)
    parser.add_argument(
        "--allow-omitted-raw",
        action="store_true",
        help=(
            "Reproduce from a release that intentionally omits every raw model "
            "transcript; retained raw subsets and hash mismatches still fail."
        ),
    )
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--no-compile", action="store_true")
    args = parser.parse_args()

    run_dir = args.run_dir.resolve()
    development_dir = (
        args.development_run_dir.resolve() if args.development_run_dir else None
    )
    external_dir = args.external_run_dir.resolve() if args.external_run_dir else None
    human_analysis = args.human_analysis.resolve() if args.human_analysis else None
    simulated_analysis = (
        args.simulated_analysis.resolve() if args.simulated_analysis else None
    )
    verified = {"synthetic": verify_complete_run(run_dir)}
    if development_dir is not None:
        verified["development"] = verify_complete_run(
            development_dir,
            allow_manifest_only_benchmark=True,
        )
    if external_dir is not None:
        verified["external"] = verify_complete_run(external_dir)
    if human_analysis is not None:
        human = json.loads(human_analysis.read_text())
        if human["source_sha256"]["records"] != verified["synthetic"][
            "records_sha256"
        ]:
            raise ValueError("human analysis is not bound to the synthetic run")
        verified["human_analysis_sha256"] = _sha256(human_analysis)
    if simulated_analysis is not None:
        simulated = json.loads(simulated_analysis.read_text())
        if "not expert validation" not in simulated["validity_boundary"]:
            raise ValueError("simulated analysis lacks the required validity boundary")
        if simulated["source_sha256"]["records"] != verified["synthetic"][
            "records_sha256"
        ]:
            raise ValueError("simulated analysis is not bound to the synthetic run")
        verified["simulated_analysis_sha256"] = _sha256(simulated_analysis)

    if not args.skip_tests:
        _run(sys.executable, "generate_warrant_benchmark.py", "--check-only", cwd=PROJECT_ROOT)
        _run(sys.executable, "-m", "pytest", "-q", cwd=PROJECT_ROOT)

    for selected in (run_dir, external_dir):
        if selected is None:
            continue
        result_args = [sys.executable, "run_warrant_results.py", str(selected)]
        if args.allow_omitted_raw:
            result_args.append("--allow-omitted-raw")
        _run(*result_args, cwd=PROJECT_ROOT)
        _run(
            sys.executable,
            "run_warrant_statistics.py",
            str(selected),
            "--bootstrap-resamples",
            str(args.bootstrap_resamples),
            cwd=PROJECT_ROOT,
        )

    confidence_audit = None
    if development_dir is not None:
        confidence_audit = run_dir / "confidence_audit.json"
        _run(
            sys.executable,
            "run_warrant_confidence_audit.py",
            str(development_dir),
            str(run_dir),
            "--output",
            str(confidence_audit),
            cwd=PROJECT_ROOT,
        )
        verified["confidence_audit_sha256"] = _sha256(confidence_audit)

    paper_args = [
        sys.executable,
        str(PAPER_DIR / "generate_paper_artifacts.py"),
        str(run_dir),
    ]
    if external_dir is not None:
        paper_args.extend(("--external-run-dir", str(external_dir)))
    if confidence_audit is not None:
        paper_args.extend(("--confidence-audit", str(confidence_audit)))
    if human_analysis is not None:
        paper_args.extend(("--human-analysis", str(human_analysis)))
    if simulated_analysis is not None:
        paper_args.extend(("--simulated-analysis", str(simulated_analysis)))
    _run(*paper_args, cwd=MONOREPO_ROOT)

    if not args.no_compile:
        tectonic = shutil.which("tectonic")
        if tectonic is None:
            raise RuntimeError(
                "tectonic is required to compile the paper; rerun with --no-compile "
                "to regenerate analysis artifacts only"
            )
        ensure_paper_build_dir()
        _run(
            tectonic,
            "--keep-logs",
            "--keep-intermediates",
            "--outdir",
            "build",
            "paper.tex",
            cwd=PAPER_DIR,
        )

    print(json.dumps(verified, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
