#!/usr/bin/env python3
"""Build a deterministic, identity-scanned anonymous WarrantLab artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from pypdf import PdfReader


FRAMEWORK_ROOT = Path(__file__).resolve().parent
REPO_ROOT = FRAMEWORK_ROOT.parent
PAPER_ROOT = REPO_ROOT / "conference_paper"
ARTIFACT_SCHEMA_VERSION = "warrantlab-anonymous-artifact-v1.5"
RELEASE_CLEARANCE_SCHEMA_VERSION = "warrantlab-release-clearance-v1.0"
RELEASE_TARGETS = ("local-validation", "anonymous-review", "public-release")
REQUIRED_RELEASE_GATES = (
    "code_license",
    "original_benchmark_license",
    "paper_release_terms",
    "endpoint_output_redistribution",
)
FROZEN_ENDPOINT_SHA256 = (
    "b70491802b316a1f01c0d461a3a335fb8e886052d7a998d2afc9cad4c785bb37"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

ROOT_FILES = (
    "THIRD_PARTY_NOTICES.md",
)

PRIVATE_NAMES = {
    ".env",
    ".DS_Store",
    "records.private-original.jsonl",
}
PRIVATE_SUFFIXES = {".key", ".pem"}
TEXT_SUFFIXES = {
    ".bib",
    ".cfg",
    ".csv",
    ".html",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".sty",
    ".tex",
    ".txt",
    ".yaml",
    ".yml",
}

PAPER_FILES = (
    "conference_paper/paper.tex",
    "conference_paper/references.bib",
    "conference_paper/usenix.sty",
    "conference_paper/generate_paper_artifacts.py",
    "conference_paper/REFERENCE_AUDIT.md",
    "conference_paper/SUBMISSION_READINESS.md",
)

FRAMEWORK_FILES = (
    "forensic-framework/requirements-research.txt",
    "forensic-framework/requirements-research.lock",
    "forensic-framework/generate_warrant_benchmark.py",
    "forensic-framework/prepare_cert_warrant_external.py",
    "forensic-framework/run_warrant_baselines.py",
    "forensic-framework/run_warrant_llm.py",
    "forensic-framework/run_warrant_results.py",
    "forensic-framework/run_warrant_confidence_audit.py",
    "forensic-framework/run_warrant_statistics.py",
    "forensic-framework/run_cert_warrant_external.py",
    "forensic-framework/prepare_warrant_annotations.py",
    "forensic-framework/prepare_warrant_adjudication.py",
    "forensic-framework/analyze_warrant_annotations.py",
    "forensic-framework/analyze_warrant_simulated_review.py",
    "forensic-framework/run_warrant_simulated_review.py",
    "forensic-framework/prepare_targeted_human_review.py",
    "forensic-framework/sanitize_warrant_release.py",
    "forensic-framework/reproduce_warrant_paper.py",
    "forensic-framework/build_anonymous_artifact.py",
    "forensic-framework/verify_anonymous_artifact.py",
    "forensic-framework/app/__init__.py",
    "forensic-framework/app/evaluation/__init__.py",
    "forensic-framework/app/evaluation/claims.py",
    "forensic-framework/app/evaluation/warrant.py",
    "forensic-framework/app/evaluation/warrant_annotations.py",
    "forensic-framework/app/evaluation/warrant_baselines.py",
    "forensic-framework/app/evaluation/warrant_human.py",
    "forensic-framework/app/evaluation/warrant_results.py",
    "forensic-framework/app/evaluation/warrant_stats.py",
    "forensic-framework/app/evaluation/warrant_simulated.py",
    "forensic-framework/app/ingestion/__init__.py",
    "forensic-framework/app/ingestion/warrant_benchmark.py",
    "forensic-framework/app/ingestion/warrant_external.py",
    "forensic-framework/app/ingestion/adapters/__init__.py",
    "forensic-framework/app/ingestion/adapters/cert_insider.py",
    "forensic-framework/app/llm/__init__.py",
    "forensic-framework/app/llm/warrant_client.py",
    "forensic-framework/app/llm/warrant_prompts.py",
    "forensic-framework/app/llm/warrant_runner.py",
    "forensic-framework/config/warrant_study.yaml",
    "forensic-framework/config/warrant_simulated_review.yaml",
    "forensic-framework/config/ollama/Modelfile.gemma4-e4b-warrant",
    "forensic-framework/tests/__init__.py",
    "forensic-framework/tests/conftest.py",
    "forensic-framework/tests/test_anonymous_artifact.py",
    "forensic-framework/tests/test_cert_adapter.py",
    "forensic-framework/tests/test_paper_artifacts.py",
    "forensic-framework/tests/test_prepare_warrant_annotations.py",
    "forensic-framework/tests/test_warrant.py",
    "forensic-framework/tests/test_warrant_annotations.py",
    "forensic-framework/tests/test_warrant_baselines.py",
    "forensic-framework/tests/test_warrant_benchmark.py",
    "forensic-framework/tests/test_warrant_external.py",
    "forensic-framework/tests/test_warrant_human.py",
    "forensic-framework/tests/test_warrant_llm_runner.py",
    "forensic-framework/tests/test_warrant_release.py",
    "forensic-framework/tests/test_warrant_reproduction.py",
    "forensic-framework/tests/test_warrant_stats.py",
    "forensic-framework/tests/test_warrant_simulated.py",
    "forensic-framework/tests/test_verify_anonymous_artifact.py",
)

SOURCE_TREES = (
    "forensic-framework/data/warrant_benchmark",
    "forensic-framework/data/warrant_external",
    "forensic-framework/docs",
)

CERT_NOTICE_METADATA = {
    "source_creator": "Brian Lindauer",
    "source_doi": "10.1184/R1/12841247.v1",
    "source_license": "CC BY 4.0",
    "source_license_url": "https://creativecommons.org/licenses/by/4.0/",
    "source_record_url": "https://kilthub.cmu.edu/articles/dataset/12841247",
}
CERT_NOTICE_PATHS = (
    "forensic-framework/data/warrant_external/",
    (
        "forensic-framework/data/warrant_runs/"
        "external-cert-r4_2-remote-fusion-gemma-v1_4-r3/"
    ),
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_release_notice() -> dict:
    """Bind the top-level notice to authoritative external-data metadata."""

    notice_path = REPO_ROOT / "THIRD_PARTY_NOTICES.md"
    manifest_path = (
        REPO_ROOT
        / "forensic-framework/data/warrant_external/cert_r4_2_manifest.json"
    )
    if not notice_path.is_file():
        raise FileNotFoundError(notice_path)
    if not manifest_path.is_file():
        raise FileNotFoundError(manifest_path)
    notice = notice_path.read_text()
    external_manifest = json.loads(manifest_path.read_text())
    for field, expected in CERT_NOTICE_METADATA.items():
        if external_manifest.get(field) != expected:
            raise ValueError(
                f"external manifest {field} does not match audited metadata"
            )
        display_value = (
            f"https://doi.org/{expected}" if field == "source_doi" else expected
        )
        if display_value not in notice:
            raise ValueError(f"third-party notice omits {field}")
    for affected_path in CERT_NOTICE_PATHS:
        if affected_path not in notice:
            raise ValueError(
                f"third-party notice omits affected path: {affected_path}"
            )
    for statement in (
        "Modifications made for this study",
        "No endorsement",
        "disclaimer of warranties",
    ):
        if statement not in notice:
            raise ValueError(f"third-party notice omits required statement: {statement}")
    return {
        "path": "THIRD_PARTY_NOTICES.md",
        "sha256": sha256(notice_path),
        "external_source_license": CERT_NOTICE_METADATA["source_license"],
        "status": "validated",
    }


def validate_release_clearance(
    path: Path,
    *,
    distribution_target: str,
    release_notice_summary: dict,
) -> dict:
    """Validate human release attestations and enforce the requested target.

    A local-validation build may retain pending gates, but it is explicitly
    marked as non-distributable. Reviewer and public builds fail closed until
    every required decision has a dated, checksum-bound evidence reference.
    """

    if distribution_target not in RELEASE_TARGETS:
        raise ValueError(f"unsupported distribution target: {distribution_target}")
    path = _within_repo(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    try:
        clearance = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ValueError(f"cannot parse release clearance: {exc}") from exc
    if clearance.get("release_clearance_schema_version") != RELEASE_CLEARANCE_SCHEMA_VERSION:
        raise ValueError("unsupported release-clearance schema")

    endpoint = clearance.get("endpoint_context")
    if not isinstance(endpoint, dict):
        raise ValueError("release clearance lacks endpoint_context")
    if endpoint.get("endpoint_sha256") != FROZEN_ENDPOINT_SHA256:
        raise ValueError("release clearance does not identify the frozen endpoint")
    if endpoint.get("deployment_platform") != "Modal":
        raise ValueError("release clearance deployment platform must be Modal")
    if endpoint.get("public_endpoint") is not True:
        raise ValueError("release clearance must record the public endpoint boundary")
    account_holder_status = endpoint.get("account_holder_status")
    if account_holder_status not in {"unverified", "verified"}:
        raise ValueError("invalid endpoint account-holder status")

    notice = clearance.get("third_party_notice")
    if not isinstance(notice, dict):
        raise ValueError("release clearance lacks third_party_notice")
    if notice.get("status") != "validated":
        raise ValueError("third-party notice is not marked validated")
    if notice.get("sha256") != release_notice_summary.get("sha256"):
        raise ValueError("release clearance third-party notice hash is stale")

    gates = clearance.get("gates")
    if not isinstance(gates, dict):
        raise ValueError("release clearance lacks gates")
    if set(gates) != set(REQUIRED_RELEASE_GATES):
        raise ValueError("release clearance gate set does not match the schema")
    outstanding: list[str] = []
    approved: list[str] = []
    for gate_name in REQUIRED_RELEASE_GATES:
        gate = gates.get(gate_name)
        if not isinstance(gate, dict):
            raise ValueError(f"release clearance lacks gate: {gate_name}")
        status = gate.get("status")
        if status == "pending":
            if any(
                gate.get(field) is not None
                for field in ("decision", "evidence_sha256", "approved_utc")
            ):
                raise ValueError(
                    f"pending release gate contains approval data: {gate_name}"
                )
            outstanding.append(gate_name)
            continue
        if status != "approved":
            raise ValueError(f"invalid release gate status for {gate_name}: {status!r}")
        decision = gate.get("decision")
        evidence_sha256 = gate.get("evidence_sha256")
        approved_utc = gate.get("approved_utc")
        if not isinstance(decision, str) or not decision.strip():
            raise ValueError(f"approved release gate lacks a decision: {gate_name}")
        if not isinstance(evidence_sha256, str) or not SHA256_RE.fullmatch(
            evidence_sha256
        ):
            raise ValueError(
                f"approved release gate lacks a valid evidence SHA-256: {gate_name}"
            )
        if not isinstance(approved_utc, str) or not UTC_TIMESTAMP_RE.fullmatch(
            approved_utc
        ):
            raise ValueError(
                f"approved release gate lacks a UTC approval timestamp: {gate_name}"
            )
        approved.append(gate_name)

    if (
        gates["endpoint_output_redistribution"].get("status") == "approved"
        and account_holder_status != "verified"
    ):
        raise ValueError(
            "endpoint-output approval requires verified account-holder status"
        )

    if distribution_target != "local-validation" and outstanding:
        raise ValueError(
            f"{distribution_target} release blocked by pending gates: "
            + ", ".join(outstanding)
        )
    status = {
        "local-validation": "local_validation_only_not_cleared_for_distribution",
        "anonymous-review": "cleared_for_anonymous_review",
        "public-release": "cleared_for_public_release",
    }[distribution_target]
    return {
        "path": "forensic-framework/config/release_clearance.json",
        "sha256": sha256(path),
        "requested_target": distribution_target,
        "status": status,
        "contains_structured_model_output": True,
        "endpoint_sha256": FROZEN_ENDPOINT_SHA256,
        "approved_gates": approved,
        "outstanding_gates": outstanding,
    }


def _within_repo(path: Path) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(REPO_ROOT.resolve())
    except ValueError as exc:
        raise ValueError(f"artifact source is outside repository: {path}") from exc
    return resolved


def _safe_source_file(path: Path) -> bool:
    return (
        path.is_file()
        and not path.is_symlink()
        and path.name not in PRIVATE_NAMES
        and path.suffix.lower() not in PRIVATE_SUFFIXES
        and "__pycache__" not in path.parts
        and ".pytest_cache" not in path.parts
        and ".git" not in path.parts
    )


def files_in_tree(path: Path, *, include_raw: bool = True) -> list[Path]:
    root = _within_repo(path)
    if not root.is_dir():
        raise FileNotFoundError(root)
    files = []
    for candidate in sorted(root.rglob("*")):
        if not _safe_source_file(candidate):
            continue
        if not include_raw and "raw" in candidate.relative_to(root).parts:
            continue
        files.append(candidate)
    return files


def validate_release_run(run_dir: Path) -> dict:
    """Require a complete run whose public records match its redaction manifest."""

    run_dir = _within_repo(run_dir)
    manifest_path = run_dir / "manifest.json"
    records_path = run_dir / "records.jsonl"
    release_path = run_dir / "release_redactions.json"
    for required in (manifest_path, records_path, release_path):
        if not required.is_file():
            raise FileNotFoundError(f"release run is missing {required.name}: {run_dir}")
    manifest = json.loads(manifest_path.read_text())
    release = json.loads(release_path.read_text())
    counts = manifest.get("counts_for_this_invocation", {})
    planned = counts.get("planned")
    completed = counts.get("completed")
    record_count = sum(1 for line in records_path.read_text().splitlines() if line.strip())
    if not isinstance(planned, int) or completed != planned or record_count != planned:
        raise ValueError(
            f"run is incomplete: planned={planned}, completed={completed}, "
            f"records={record_count}"
        )
    if release.get("post_redaction_records_sha256") != sha256(records_path):
        raise ValueError("records do not match release_redactions.json")
    if release.get("run_id") != manifest.get("run_id"):
        raise ValueError("run ID differs between run and release manifests")
    return {
        "run_id": manifest["run_id"],
        "path": run_dir.relative_to(REPO_ROOT.resolve()).as_posix(),
        "record_count": record_count,
        "records_sha256": sha256(records_path),
        "manifest_sha256": sha256(manifest_path),
        "benchmark_sha256": manifest.get("benchmark_sha256"),
    }


def validate_confidence_audit(
    path: Path,
    *,
    development_records_sha256: str,
    test_records_sha256: str,
    development_manifest_sha256: str,
    test_manifest_sha256: str,
    development_benchmark_sha256: str,
    test_benchmark_sha256: str,
) -> dict:
    """Require a no-tuning audit bound to the packaged development/test runs."""

    path = _within_repo(path)
    if not path.is_file():
        raise FileNotFoundError(path)
    audit = json.loads(path.read_text())
    if (
        audit.get("confidence_audit_schema_version")
        != "warrant-confidence-audit-v1.1"
    ):
        raise ValueError("unsupported confidence-audit schema")
    sources = audit.get("source_sha256") or {}
    if sources.get("development_records") != development_records_sha256:
        raise ValueError("confidence audit is not bound to the development records")
    if sources.get("test_records") != test_records_sha256:
        raise ValueError("confidence audit is not bound to the test records")
    if sources.get("development_manifest") != development_manifest_sha256:
        raise ValueError("confidence audit is not bound to the development manifest")
    if sources.get("test_manifest") != test_manifest_sha256:
        raise ValueError("confidence audit is not bound to the test manifest")
    alignment = audit.get("benchmark_alignment") or {}
    if alignment.get("development_benchmark_sha256") != development_benchmark_sha256:
        raise ValueError("confidence audit development benchmark hash mismatch")
    if alignment.get("test_benchmark_sha256") != test_benchmark_sha256:
        raise ValueError("confidence audit test benchmark hash mismatch")
    decision = audit.get("calibrator_fit_decision") or {}
    if (
        decision.get("status") != "not_fit"
        or decision.get("threshold_selected") is not None
    ):
        raise ValueError("confidence audit must not tune a replacement threshold")
    if "No calibrator or replacement threshold" not in audit.get(
        "held_out_use_boundary", ""
    ):
        raise ValueError("confidence audit lacks the held-out no-tuning boundary")
    return {
        "path": path.relative_to(REPO_ROOT.resolve()).as_posix(),
        "sha256": sha256(path),
        "calibrator_fit_status": "not_fit",
        "replacement_threshold_selected": False,
    }


def validate_simulated_review(run_dir: Path) -> dict:
    """Validate a complete non-human reviewer panel and its derived analysis."""

    run_dir = _within_repo(run_dir)
    manifest_path = run_dir / "manifest.json"
    analysis_path = run_dir / "analysis.json"
    consensus_path = run_dir / "consensus.jsonl"
    for required in (manifest_path, analysis_path, consensus_path):
        if not required.is_file():
            raise FileNotFoundError(
                f"simulated review is missing {required.name}: {run_dir}"
            )
    manifest = json.loads(manifest_path.read_text())
    analysis = json.loads(analysis_path.read_text())
    boundary = "not human or expert validation"
    if boundary not in manifest.get("validity_boundary", ""):
        raise ValueError("simulated-run manifest lacks the non-expert boundary")
    if "not expert validation" not in analysis.get("validity_boundary", ""):
        raise ValueError("simulated analysis lacks the non-expert boundary")
    item_count = int(manifest["item_count"])
    consensus_count = sum(
        1 for line in consensus_path.read_text().splitlines() if line.strip()
    )
    if consensus_count != item_count:
        raise ValueError(
            f"simulated consensus incomplete: {consensus_count} != {item_count}"
        )
    reviewers = [
        reviewer["reviewer_id"]
        for reviewer in manifest["reviewers"]
        if reviewer["panel_role"] == "consensus"
    ]
    if len(reviewers) != 3:
        raise ValueError("simulated consensus panel must contain three reviewers")
    judgment_hashes = analysis["source_sha256"]["judgments"]
    for reviewer in reviewers:
        judgments = run_dir / "reviewers" / reviewer / "judgments.jsonl"
        if not judgments.is_file():
            raise FileNotFoundError(judgments)
        count = sum(1 for line in judgments.read_text().splitlines() if line.strip())
        if count != item_count:
            raise ValueError(
                f"simulated reviewer incomplete: {reviewer} {count} != {item_count}"
            )
        if judgment_hashes.get(reviewer) != sha256(judgments):
            raise ValueError(f"simulated judgment hash mismatch: {reviewer}")
    if analysis["source_sha256"]["simulated_run_manifest"] != sha256(manifest_path):
        raise ValueError("simulated analysis is not bound to its run manifest")
    return {
        "run_id": manifest["run_id"],
        "path": run_dir.relative_to(REPO_ROOT.resolve()).as_posix(),
        "reviewer_count": len(reviewers),
        "item_count": item_count,
        "analysis_sha256": sha256(analysis_path),
        "consensus_sha256": sha256(consensus_path),
        "raw_responses_included": False,
        "validity_boundary": analysis["validity_boundary"],
    }


def _git_value(key: str) -> str | None:
    result = subprocess.run(
        ["git", "config", "--get", key],
        cwd=REPO_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    value = result.stdout.strip()
    return value or None


def default_identity_terms() -> list[str]:
    terms = {
        Path.home().name,
        str(Path.home()),
        str(REPO_ROOT.resolve()),
    }
    for key in ("user.name", "user.email"):
        value = _git_value(key)
        if value:
            terms.add(value)
    return sorted(term for term in terms if len(term.strip()) >= 4)


def scan_release_tree(root: Path, *, identity_terms: list[str]) -> list[dict[str, str]]:
    """Return identity, workstation-path, and credential-like release violations."""

    identity_bytes = [term.casefold().encode() for term in identity_terms]
    path_patterns = (
        re.compile(r"/" + r"Users/[^/\s]+", re.IGNORECASE),
        re.compile(r"/" + r"home/[^/\s]+", re.IGNORECASE),
        re.compile(r"[A-Za-z]:\\" + r"Users\\[^\\\s]+", re.IGNORECASE),
    )
    secret_patterns = (
        re.compile(r"\b" + r"AKIA[0-9A-Z]{16}\b"),
        re.compile(r"\b" + r"gh[pousr]_[A-Za-z0-9]{20,}\b"),
        re.compile(r"\b" + r"sk" + r"-[A-Za-z0-9_-]{20,}\b"),
        re.compile(r"(?i)(api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_./+-]{16,}"),
    )
    issue_keys: set[tuple[str, str]] = set()
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if "__pycache__" in path.parts or path.suffix.lower() == ".pyc":
            issue_keys.add((relative, "generated_cache_file"))
            continue
        if path.name in PRIVATE_NAMES or path.suffix.lower() in PRIVATE_SUFFIXES:
            issue_keys.add((relative, "private_filename"))
            continue
        data = path.read_bytes()
        folded = data.lower()
        for index, term in enumerate(identity_bytes, start=1):
            if term and term in folded:
                issue_keys.add((relative, f"identity_term_{index}"))
        text = ""
        if path.suffix.lower() in TEXT_SUFFIXES:
            text = data.decode("utf-8", errors="replace")
        elif path.suffix.lower() == ".pdf":
            try:
                reader = PdfReader(path)
                metadata = "\n".join(
                    f"{key}: {value}" for key, value in (reader.metadata or {}).items()
                )
                pages = "\n".join(page.extract_text() or "" for page in reader.pages)
                text = metadata + "\n" + pages
            except Exception:  # pragma: no cover - defensive release failure
                issue_keys.add((relative, "pdf_parse_failure"))
        extracted = text.casefold().encode()
        for index, term in enumerate(identity_bytes, start=1):
            if term and term in extracted:
                issue_keys.add((relative, f"identity_term_{index}"))
        if any(pattern.search(text) for pattern in path_patterns):
            issue_keys.add((relative, "absolute_user_path"))
        if any(pattern.search(text) for pattern in secret_patterns):
            issue_keys.add((relative, "credential_like_value"))
    return [
        {"file": file, "rule": rule}
        for file, rule in sorted(issue_keys)
    ]


def _copy_file(source: Path, staging_root: Path, destination: Path | None = None) -> None:
    source = _within_repo(source)
    if not _safe_source_file(source):
        raise ValueError(f"unsafe artifact source: {source}")
    relative = destination or source.relative_to(REPO_ROOT)
    target = staging_root / relative
    if target.exists() and sha256(target) != sha256(source):
        raise ValueError(f"artifact destination collision: {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)


def _copy_tree(source: Path, staging_root: Path, *, include_raw: bool = True) -> None:
    for path in files_in_tree(source, include_raw=include_raw):
        _copy_file(path, staging_root)


def _run_staged(args: list[str], *, cwd: Path) -> None:
    """Run one deterministic derivation inside the staged release tree."""

    result = subprocess.run(
        args,
        cwd=cwd,
        check=False,
        capture_output=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        text=True,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise ValueError(
            f"staged artifact derivation failed ({' '.join(args)}): {detail}"
        )


def _normalize_omitted_raw_derivatives(
    staging: Path,
    *,
    run_summaries: dict,
    has_human_analysis: bool,
    has_simulated_analysis: bool,
) -> None:
    """Bind packaged analyses to the archive's all-raw-omitted context.

    Repository analyses are produced where raw transcripts are available and
    therefore report them as hash-verified. An omitted-raw reviewer archive has
    a different, deliberate integrity state. Regenerating the analyses inside
    the staged tree makes that state truthful and makes the documented
    clean-room command byte-stable for every manifest-listed derivative.
    """

    framework = staging / "forensic-framework"
    paper = staging / "conference_paper"
    for run in run_summaries.values():
        run_path = staging / run["path"]
        _run_staged(
            [
                sys.executable,
                "run_warrant_results.py",
                str(run_path),
                "--allow-omitted-raw",
            ],
            cwd=framework,
        )
        analysis = json.loads((run_path / "analysis.json").read_text())
        integrity = analysis.get("artifact_integrity") or {}
        referenced = integrity.get("unique_raw_responses_referenced")
        if (
            not integrity.get("ok")
            or integrity.get("raw_response_status")
            != "omitted_by_release_policy"
            or integrity.get("unique_raw_responses_checked") != 0
            or not isinstance(referenced, int)
            or referenced <= 0
            or integrity.get("unique_raw_responses_missing") != referenced
        ):
            raise ValueError(
                f"staged omitted-raw integrity normalization failed: {run_path}"
            )

    synthetic = staging / run_summaries["synthetic_confirmatory"]["path"]
    paper_args = [
        sys.executable,
        str(paper / "generate_paper_artifacts.py"),
        str(synthetic),
        "--paper-dir",
        str(paper),
        "--confidence-audit",
        str(synthetic / "confidence_audit.json"),
    ]
    if "external_transfer" in run_summaries:
        paper_args.extend(
            (
                "--external-run-dir",
                str(staging / run_summaries["external_transfer"]["path"]),
            )
        )
    if has_human_analysis:
        paper_args.extend(
            (
                "--human-analysis",
                str(staging / "human-validation" / "adjudicated_analysis.json"),
            )
        )
    if has_simulated_analysis:
        paper_args.extend(
            (
                "--simulated-analysis",
                str(staging / "simulated-ai-review" / "analysis.json"),
            )
        )
    _run_staged(paper_args, cwd=staging)


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _tracked_tree_dirty() -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def _write_readme(
    path: Path,
    *,
    include_raw: bool,
    has_human_package: bool,
    has_human_analysis: bool,
    run_summaries: dict,
    has_simulated_analysis: bool = False,
    release_clearance: dict,
) -> None:
    if has_human_analysis:
        human_note = (
            "The blinded annotation package and checksum-bound adjudicated "
            "expert analysis are included."
        )
    elif has_human_package:
        human_note = (
            "The blinded, unfilled annotation package is included, but no "
            "adjudicated expert analysis exists. Do not treat mechanical proxy "
            "labels as expert validation."
        )
    else:
        human_note = (
            "No human-annotation package or adjudicated expert analysis is "
            "included; do not treat mechanical proxy labels as expert validation."
        )
    raw_note = (
        "Raw model transcripts are included for output-level audit."
        if include_raw
        else (
            "Raw model transcripts are omitted; scored structured records are included. "
            "Packaged analyses record complete release-policy omission and are "
            "byte-stable under the reproduction command."
        )
    )
    synthetic_path = Path(run_summaries["synthetic_confirmatory"]["path"])
    synthetic_arg = synthetic_path.relative_to("forensic-framework").as_posix()
    command = (
        ".venv/bin/python reproduce_warrant_paper.py " + synthetic_arg
    )
    development_path = Path(run_summaries["development"]["path"])
    development_arg = development_path.relative_to("forensic-framework").as_posix()
    command += " --development-run-dir " + development_arg
    if "external_transfer" in run_summaries:
        external_path = Path(run_summaries["external_transfer"]["path"])
        external_arg = external_path.relative_to("forensic-framework").as_posix()
        command += " --external-run-dir " + external_arg
    if has_human_analysis:
        command += " --human-analysis ../human-validation/adjudicated_analysis.json"
    if has_simulated_analysis:
        command += " --simulated-analysis ../simulated-ai-review/analysis.json"
    if not include_raw:
        command += " --allow-omitted-raw"

    distribution_banner = (
        "DISTRIBUTION STATUS: LOCAL VALIDATION ONLY — DO NOT UPLOAD OR SHARE."
        if release_clearance["status"]
        == "local_validation_only_not_cleared_for_distribution"
        else "DISTRIBUTION STATUS: "
        + release_clearance["status"].replace("_", " ").upper()
        + "."
    )
    outstanding = release_clearance["outstanding_gates"]
    outstanding_note = (
        " Pending gates: `" + "`, `".join(outstanding) + "`."
        if outstanding
        else " All required release attestations are recorded."
    )

    path.write_text(
        "# WarrantLab anonymous artifact\n\n"
        + "**"
        + distribution_banner
        + "**"
        + outstanding_note
        + "\n\n"
        + """This artifact accompanies the anonymous paper *The Forensic Warrant Gap*.
It contains the frozen benchmark, analysis code, model-run records, statistical
outputs, paper source, and a rendered manuscript. No network access is required
to reproduce the reported analyses or rebuild the paper after installing the
locked research dependencies.

## Requirements and expected cost

- Python 3.11 or newer and Tectonic (validated with Tectonic 0.17.0).
- About 1 GB of free disk for the virtual environment and regenerated outputs.
- No GPU, model server, API credential, or model download. Reproduction uses
  frozen scored records and does not call Gemma or any remote endpoint.
- On the reference laptop, dependency installation plus the full command takes
  under two minutes; allow up to five minutes on a typical current CPU. Network
  access is needed only for the one-time dependency installation.

## Reproduction

From the artifact root:

```bash
python3 forensic-framework/verify_anonymous_artifact.py --strict .
python3 -m venv forensic-framework/.venv
forensic-framework/.venv/bin/python -m pip install -r forensic-framework/requirements-research.lock
cd forensic-framework
"""
        + command
        + """
```

The command validates run cardinality, case-ID and release-record hashes,
packaged benchmark hashes where the manifest records a source path, and either
retained raw-response hashes or the all-raw-omitted release policy before
regenerating tables, figures, statistics, and the PDF. The historical
development manifest predates its benchmark-path field; its stored benchmark
digest is disclosed but cannot be rechecked against absent source bytes.

"""
        + raw_note
        + "\n\n"
        + human_note
        + (
            "\n\nThe `simulated-ai-review` directory contains an exploratory "
            "language-model judge sensitivity panel. It is not human or expert "
            "validation, and raw simulation responses are excluded."
            if has_simulated_analysis
            else ""
        )
        + """

All payload files are enumerated with SHA-256 hashes in
`ARTIFACT_MANIFEST.json`. The strict verification command checks safe canonical
paths, file sizes, and all payload hashes, and rejects unlisted files. Run it
immediately after extraction; later reproduction intentionally creates an
unlisted virtual environment and build directory. The internal manifest detects
corruption but does not authenticate the ZIP itself, so compare the ZIP's
SHA-256 with the digest published in the conference artifact record.

`THIRD_PARTY_NOTICES.md` identifies component-specific upstream terms and
affected paths. It does not grant a repository-wide license. Anonymous-review
or public release remains conditional on the human authors approving the
applicable original-material licenses and confirming the remote endpoint's
terms for the structured output content retained in scored records.
"""
    )


def _write_zip(staging_root: Path, output: Path) -> None:
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(candidate for candidate in staging_root.rglob("*") if candidate.is_file()):
            relative = path.relative_to(staging_root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o644 & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)


def default_output_for_target(distribution_target: str) -> Path:
    if distribution_target not in RELEASE_TARGETS:
        raise ValueError(f"unsupported distribution target: {distribution_target}")
    return (
        REPO_ROOT
        / "output"
        / "artifact"
        / f"warrantlab-{distribution_target}.zip"
    )


def build_artifact(
    *,
    development_run_dir: Path,
    synthetic_run_dir: Path,
    external_run_dir: Path | None,
    human_package_dir: Path | None,
    human_analysis: Path | None,
    simulated_review_dir: Path | None,
    targeted_review_dir: Path | None,
    paper_pdf: Path,
    output: Path,
    include_raw: bool,
    release_clearance_path: Path,
    distribution_target: str,
    identity_terms: list[str],
    allow_dirty: bool,
    force: bool,
) -> dict:
    if _tracked_tree_dirty() and not allow_dirty:
        raise ValueError("tracked working tree is dirty; commit changes or pass --allow-dirty")
    release_notice_summary = validate_release_notice()
    release_clearance_summary = validate_release_clearance(
        release_clearance_path,
        distribution_target=distribution_target,
        release_notice_summary=release_notice_summary,
    )
    run_summaries = {
        "development": validate_release_run(development_run_dir),
        "synthetic_confirmatory": validate_release_run(synthetic_run_dir),
    }
    if external_run_dir:
        run_summaries["external_transfer"] = validate_release_run(external_run_dir)
    confidence_audit_summary = validate_confidence_audit(
        synthetic_run_dir / "confidence_audit.json",
        development_records_sha256=run_summaries["development"]["records_sha256"],
        test_records_sha256=run_summaries["synthetic_confirmatory"]["records_sha256"],
        development_manifest_sha256=run_summaries["development"]["manifest_sha256"],
        test_manifest_sha256=run_summaries["synthetic_confirmatory"]["manifest_sha256"],
        development_benchmark_sha256=run_summaries["development"]["benchmark_sha256"],
        test_benchmark_sha256=run_summaries["synthetic_confirmatory"]["benchmark_sha256"],
    )
    human_analysis_summary = None
    simulated_review_summary = None
    if simulated_review_dir is not None:
        simulated_review_summary = validate_simulated_review(simulated_review_dir)
    if human_analysis is not None:
        human_analysis = _within_repo(human_analysis)
        if not human_analysis.is_file():
            raise FileNotFoundError(human_analysis)
        human_data = json.loads(human_analysis.read_text())
        expected_records_hash = run_summaries["synthetic_confirmatory"][
            "records_sha256"
        ]
        actual_records_hash = (human_data.get("source_sha256") or {}).get("records")
        if actual_records_hash != expected_records_hash:
            raise ValueError(
                "human analysis is not checksum-bound to the synthetic release records"
            )
        human_analysis_summary = {
            "path": "human-validation/adjudicated_analysis.json",
            "sha256": sha256(human_analysis),
        }
    paper_pdf = _within_repo(paper_pdf)
    if not paper_pdf.is_file():
        raise FileNotFoundError(paper_pdf)
    if output.exists():
        if not force:
            raise FileExistsError(f"output exists: {output}")
        if not output.is_file():
            raise ValueError(f"refusing to replace non-file output: {output}")
        output.unlink()
    output.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="warrantlab-artifact-") as temporary:
        staging = Path(temporary) / "warrantlab-anonymous-artifact"
        staging.mkdir()
        for relative in ROOT_FILES + PAPER_FILES + FRAMEWORK_FILES:
            _copy_file(REPO_ROOT / relative, staging)
        _copy_file(
            release_clearance_path,
            staging,
            Path("forensic-framework/config/release_clearance.json"),
        )
        for relative in SOURCE_TREES:
            _copy_tree(REPO_ROOT / relative, staging, include_raw=False)
        for generated in sorted(PAPER_ROOT.glob("generated_*.tex")):
            _copy_file(generated, staging)
        for figure in (
            PAPER_ROOT / "figures" / "warrant-study-design.pdf",
            PAPER_ROOT / "figures" / "coverage-risk.pdf",
        ):
            _copy_file(figure, staging)
        for run_dir in (development_run_dir, synthetic_run_dir, external_run_dir):
            if run_dir:
                _copy_tree(run_dir, staging, include_raw=include_raw)
        if human_package_dir:
            human_root = _within_repo(human_package_dir)
            for source in files_in_tree(human_root, include_raw=False):
                destination = Path("human-validation") / source.relative_to(human_root)
                _copy_file(source, staging, destination)
        if human_analysis is not None:
            _copy_file(
                human_analysis,
                staging,
                Path("human-validation") / "adjudicated_analysis.json",
            )
        if simulated_review_dir is not None:
            simulated_root = _within_repo(simulated_review_dir)
            for source in files_in_tree(simulated_root, include_raw=False):
                destination = (
                    Path("simulated-ai-review") / source.relative_to(simulated_root)
                )
                _copy_file(source, staging, destination)
        if targeted_review_dir is not None:
            targeted_root = _within_repo(targeted_review_dir)
            for source in files_in_tree(targeted_root, include_raw=False):
                destination = (
                    Path("targeted-human-review") / source.relative_to(targeted_root)
                )
                _copy_file(source, staging, destination)
        if not include_raw:
            _normalize_omitted_raw_derivatives(
                staging,
                run_summaries=run_summaries,
                has_human_analysis=human_analysis is not None,
                has_simulated_analysis=simulated_review_dir is not None,
            )
        _copy_file(paper_pdf, staging, Path("paper") / "warrantlab-paper.pdf")
        _write_readme(
            staging / "ARTIFACT_README.md",
            include_raw=include_raw,
            has_human_package=human_package_dir is not None,
            has_human_analysis=human_analysis is not None,
            run_summaries=run_summaries,
            has_simulated_analysis=simulated_review_dir is not None,
            release_clearance=release_clearance_summary,
        )

        issues = scan_release_tree(staging, identity_terms=identity_terms)
        if issues:
            preview = ", ".join(f"{item['file']} ({item['rule']})" for item in issues[:10])
            raise ValueError(f"anonymous release scan failed: {preview}")

        files = []
        for path in sorted(candidate for candidate in staging.rglob("*") if candidate.is_file()):
            relative = path.relative_to(staging).as_posix()
            files.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256(path)})
        manifest = {
            "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
            "source_commit": _git_commit(),
            "identity_scan": {
                "status": "passed",
                "term_count": len(identity_terms),
                "absolute_path_scan": True,
                "credential_pattern_scan": True,
            },
            "include_raw_model_transcripts": include_raw,
            "third_party_notice": release_notice_summary,
            "release_clearance": release_clearance_summary,
            "paper_pdf_sha256": sha256(paper_pdf),
            "runs": run_summaries,
            "confidence_audit": confidence_audit_summary,
            "human_annotation_package_included": human_package_dir is not None,
            "human_adjudicated_analysis_included": human_analysis is not None,
            "human_package_path": "human-validation" if human_package_dir else None,
            "human_analysis": human_analysis_summary,
            "simulated_ai_review": simulated_review_summary,
            "targeted_human_review_package_included": targeted_review_dir is not None,
            "targeted_human_review_path": (
                "targeted-human-review" if targeted_review_dir else None
            ),
            "files": files,
        }
        manifest_path = staging / "ARTIFACT_MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        post_manifest_issues = scan_release_tree(staging, identity_terms=identity_terms)
        if post_manifest_issues:
            raise ValueError("generated artifact manifest failed the anonymous release scan")
        _write_zip(staging, output)
    manifest["archive_sha256"] = sha256(output)
    manifest["archive_bytes"] = output.stat().st_size
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development-run-dir", required=True, type=Path)
    parser.add_argument("--synthetic-run-dir", required=True, type=Path)
    parser.add_argument("--external-run-dir", type=Path)
    parser.add_argument("--human-package-dir", type=Path)
    parser.add_argument("--human-analysis", type=Path)
    parser.add_argument("--simulated-review-dir", type=Path)
    parser.add_argument("--targeted-review-dir", type=Path)
    parser.add_argument(
        "--paper-pdf",
        type=Path,
        default=PAPER_ROOT / "build" / "paper.pdf",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "archive path; defaults to output/artifact/warrantlab-"
            "<distribution-target>.zip"
        ),
    )
    parser.add_argument("--omit-raw", action="store_true")
    parser.add_argument(
        "--release-clearance",
        type=Path,
        default=FRAMEWORK_ROOT / "config" / "release_clearance.json",
    )
    parser.add_argument(
        "--distribution-target",
        choices=RELEASE_TARGETS,
        default="local-validation",
        help=(
            "local-validation permits pending gates but marks the archive as "
            "non-distributable; reviewer/public targets fail closed"
        ),
    )
    parser.add_argument("--identity-term", action="append", default=[])
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    terms = sorted(set(default_identity_terms() + args.identity_term))
    output = args.output or default_output_for_target(args.distribution_target)
    result = build_artifact(
        development_run_dir=args.development_run_dir,
        synthetic_run_dir=args.synthetic_run_dir,
        external_run_dir=args.external_run_dir,
        human_package_dir=args.human_package_dir,
        human_analysis=args.human_analysis,
        simulated_review_dir=args.simulated_review_dir,
        targeted_review_dir=args.targeted_review_dir,
        paper_pdf=args.paper_pdf,
        output=output,
        include_raw=not args.omit_raw,
        release_clearance_path=args.release_clearance,
        distribution_target=args.distribution_target,
        identity_terms=terms,
        allow_dirty=args.allow_dirty,
        force=args.force,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
