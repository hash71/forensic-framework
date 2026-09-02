#!/usr/bin/env python3
"""Verify every manifest-bound file in an extracted WarrantLab artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any


MANIFEST_NAME = "ARTIFACT_MANIFEST.json"
SUPPORTED_SCHEMA = "warrantlab-anonymous-artifact-v1.6"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RELEASE_STATUSES = {
    "local-validation": "local_validation_only_not_cleared_for_distribution",
    "anonymous-review": "cleared_for_anonymous_review",
    "public-release": "cleared_for_public_release",
}
REQUIRED_RELEASE_GATES = {
    "code_license",
    "original_benchmark_license",
    "paper_release_terms",
    "endpoint_output_redistribution",
}
RELEASE_CLEARANCE_PATH = "forensic-framework/config/release_clearance.json"
CONTENT_PROFILES = {"structured-output", "aggregate-only"}
OUTPUT_FINGERPRINT_WORDS = 16
AGGREGATE_RUN_FILES = {
    "analysis.json",
    "confidence_audit.json",
    "manifest.json",
    "release_redactions.json",
    "statistics.json",
}


class VerificationError(ValueError):
    """Raised when an artifact fails structural or payload verification."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_parts(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or not value:
        raise VerificationError("manifest file path must be a non-empty string")
    if "\\" in value or any(ord(character) < 32 for character in value):
        raise VerificationError(f"unsafe manifest file path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise VerificationError(f"unsafe manifest file path: {value!r}")
    if path.as_posix() != value or not path.parts or "." in path.parts:
        raise VerificationError(f"non-canonical manifest file path: {value!r}")
    return path.parts


def _load_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / MANIFEST_NAME
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise VerificationError(f"missing regular {MANIFEST_NAME}")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"cannot parse {MANIFEST_NAME}: {exc}") from exc
    if not isinstance(manifest, dict):
        raise VerificationError("artifact manifest must be a JSON object")
    if manifest.get("artifact_schema_version") != SUPPORTED_SCHEMA:
        raise VerificationError(
            "unsupported artifact schema: "
            f"{manifest.get('artifact_schema_version')!r}"
        )
    if not COMMIT_RE.fullmatch(str(manifest.get("source_commit", ""))):
        raise VerificationError("manifest source_commit is not a full Git SHA-1")
    content_profile = manifest.get("content_profile")
    if content_profile not in CONTENT_PROFILES:
        raise VerificationError("manifest has invalid content_profile")
    identity_scan = manifest.get("identity_scan")
    if not isinstance(identity_scan, dict) or identity_scan.get("status") != "passed":
        raise VerificationError("manifest does not record a passed identity scan")
    if not isinstance(manifest.get("files"), list) or not manifest["files"]:
        raise VerificationError("manifest files must be a non-empty array")
    clearance = manifest.get("release_clearance")
    if not isinstance(clearance, dict):
        raise VerificationError("manifest lacks release_clearance")
    target = clearance.get("requested_target")
    status = clearance.get("status")
    if target not in RELEASE_STATUSES or status != RELEASE_STATUSES.get(target):
        raise VerificationError("manifest release target and status are inconsistent")
    outstanding = clearance.get("outstanding_gates")
    approved = clearance.get("approved_gates")
    not_applicable = clearance.get("not_applicable_gates")
    if not isinstance(outstanding, list) or not all(
        isinstance(item, str) for item in outstanding
    ):
        raise VerificationError("manifest has invalid outstanding release gates")
    if not isinstance(approved, list) or not all(
        isinstance(item, str) for item in approved
    ):
        raise VerificationError("manifest has invalid approved release gates")
    if not isinstance(not_applicable, list) or not all(
        isinstance(item, str) for item in not_applicable
    ):
        raise VerificationError("manifest has invalid not-applicable release gates")
    if (
        len(outstanding) != len(set(outstanding))
        or len(approved) != len(set(approved))
        or len(not_applicable) != len(set(not_applicable))
        or set(outstanding) & set(approved)
        or set(outstanding) & set(not_applicable)
        or set(approved) & set(not_applicable)
        or set(outstanding) | set(approved) | set(not_applicable)
        != REQUIRED_RELEASE_GATES
    ):
        raise VerificationError("manifest release-gate partition is invalid")
    if target != "local-validation" and outstanding:
        raise VerificationError("distribution-cleared artifact retains pending gates")
    contains_structured = clearance.get("contains_structured_model_output")
    if content_profile == "structured-output":
        if contains_structured is not True or not_applicable:
            raise VerificationError(
                "structured-output profile has inconsistent release clearance"
            )
        if manifest.get("aggregate_only_scan") is not None:
            raise VerificationError("structured-output profile has aggregate-only scan")
        if manifest.get("aggregate_run_files") is not None:
            raise VerificationError("structured-output profile has aggregate run allowlist")
    else:
        if contains_structured is not False or set(not_applicable) != {
            "endpoint_output_redistribution"
        }:
            raise VerificationError(
                "aggregate-only profile has inconsistent release clearance"
            )
        aggregate_scan = manifest.get("aggregate_only_scan")
        if not isinstance(aggregate_scan, dict) or aggregate_scan.get("status") != "passed":
            raise VerificationError("aggregate-only profile lacks a passed output scan")
        if aggregate_scan.get("forbidden_path_scan") is not True:
            raise VerificationError("aggregate-only profile lacks a forbidden-path scan")
        if aggregate_scan.get("fingerprint_width_words") != OUTPUT_FINGERPRINT_WORDS:
            raise VerificationError("aggregate-only output fingerprint width is invalid")
        if aggregate_scan.get("verbatim_overlap_count") != 0:
            raise VerificationError("aggregate-only profile reports output overlap")
        for field in (
            "source_output_strings_fingerprinted",
            "unique_output_fingerprints",
            "release_files_scanned",
        ):
            value = aggregate_scan.get(field)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise VerificationError(
                    f"aggregate-only profile has invalid scan count: {field}"
                )
        if manifest.get("include_raw_model_transcripts") is not False:
            raise VerificationError("aggregate-only profile claims raw transcripts")
        aggregate_run_files = manifest.get("aggregate_run_files")
        if not isinstance(aggregate_run_files, dict) or not aggregate_run_files:
            raise VerificationError("aggregate-only profile lacks run-file allowlists")
        required_aggregate_files = {
            "analysis.json",
            "manifest.json",
            "release_redactions.json",
            "statistics.json",
        }
        for names in aggregate_run_files.values():
            if (
                not isinstance(names, list)
                or not required_aggregate_files.issubset(names)
                or not set(names).issubset(AGGREGATE_RUN_FILES)
            ):
                raise VerificationError("aggregate-only run-file allowlist is invalid")
        for field in (
            "human_annotation_package_included",
            "human_adjudicated_analysis_included",
            "targeted_human_review_package_included",
        ):
            if manifest.get(field) is not False:
                raise VerificationError(
                    f"aggregate-only profile has forbidden package flag: {field}"
                )
    runs = manifest.get("runs")
    if not isinstance(runs, dict) or not runs:
        raise VerificationError("manifest lacks run summaries")
    expected_records_included = content_profile == "structured-output"
    if any(
        not isinstance(summary, dict)
        or summary.get("records_included") is not expected_records_included
        for summary in runs.values()
    ):
        raise VerificationError("run-summary record inclusion contradicts content profile")
    if clearance.get("path") != RELEASE_CLEARANCE_PATH:
        raise VerificationError("manifest has invalid release-clearance path")
    if not SHA256_RE.fullmatch(str(clearance.get("sha256", ""))):
        raise VerificationError("manifest has invalid release-clearance SHA-256")
    if not SHA256_RE.fullmatch(str(clearance.get("endpoint_sha256", ""))):
        raise VerificationError("manifest has invalid endpoint SHA-256")
    return manifest


def verify_artifact(root: Path, *, strict: bool = False) -> dict[str, Any]:
    """Verify manifest structure, safe paths, sizes, and SHA-256 payload hashes.

    Strict mode also rejects files not listed by the manifest and is intended
    for use immediately after extraction, before creating a virtual environment
    or regenerated build outputs.
    """

    root = root.resolve()
    if not root.is_dir():
        raise VerificationError(f"artifact root is not a directory: {root}")
    manifest = _load_manifest(root)
    expected_paths: set[str] = set()
    bytes_verified = 0
    errors: list[str] = []

    for index, entry in enumerate(manifest["files"]):
        if not isinstance(entry, dict):
            errors.append(f"files[{index}] is not an object")
            continue
        try:
            parts = _relative_parts(entry.get("path"))
        except VerificationError as exc:
            errors.append(str(exc))
            continue
        relative = PurePosixPath(*parts).as_posix()
        if relative == MANIFEST_NAME:
            errors.append(f"{MANIFEST_NAME} must not hash itself")
            continue
        if relative in expected_paths:
            errors.append(f"duplicate manifest path: {relative}")
            continue
        expected_paths.add(relative)

        if manifest["content_profile"] == "aggregate-only":
            if (
                parts[-1] in {"records.jsonl", "records.private-original.jsonl"}
                or "raw" in parts
                or parts[0] in {"human-validation", "targeted-human-review"}
                or (
                    parts[:3]
                    == ("forensic-framework", "data", "warrant_runs")
                    and parts[-1] not in AGGREGATE_RUN_FILES
                )
                or (
                    parts[0] == "simulated-ai-review"
                    and (
                        len(parts) != 2
                        or parts[1] not in {"analysis.json", "manifest.json"}
                    )
                )
            ):
                errors.append(
                    f"aggregate-only artifact contains forbidden payload: {relative}"
                )
                continue

        expected_bytes = entry.get("bytes")
        expected_hash = entry.get("sha256")
        if (
            isinstance(expected_bytes, bool)
            or not isinstance(expected_bytes, int)
            or expected_bytes < 0
        ):
            errors.append(f"invalid byte count for {relative}")
            continue
        if not isinstance(expected_hash, str) or not SHA256_RE.fullmatch(expected_hash):
            errors.append(f"invalid SHA-256 for {relative}")
            continue

        candidate = root
        contains_symlink = False
        for part in parts:
            candidate /= part
            contains_symlink = contains_symlink or candidate.is_symlink()
        if not candidate.is_file() or contains_symlink:
            errors.append(f"missing regular payload file: {relative}")
            continue
        actual_bytes = candidate.stat().st_size
        if actual_bytes != expected_bytes:
            errors.append(
                f"size mismatch for {relative}: {actual_bytes} != {expected_bytes}"
            )
            continue
        actual_hash = _sha256(candidate)
        if actual_hash != expected_hash:
            errors.append(
                f"SHA-256 mismatch for {relative}: {actual_hash} != {expected_hash}"
            )
            continue
        bytes_verified += actual_bytes

    extras: list[str] = []
    if strict:
        for candidate in sorted(root.rglob("*")):
            if not candidate.is_file() and not candidate.is_symlink():
                continue
            relative = candidate.relative_to(root).as_posix()
            if relative != MANIFEST_NAME and relative not in expected_paths:
                extras.append(relative)
        if extras:
            errors.append(
                "unlisted files present in strict mode: " + ", ".join(extras[:20])
            )

    if errors:
        raise VerificationError("artifact verification failed:\n- " + "\n- ".join(errors))

    clearance = manifest["release_clearance"]
    clearance_entry = next(
        (
            entry
            for entry in manifest["files"]
            if isinstance(entry, dict) and entry.get("path") == RELEASE_CLEARANCE_PATH
        ),
        None,
    )
    if clearance_entry is None:
        raise VerificationError("release-clearance file is not manifest-bound")
    if clearance_entry.get("sha256") != clearance["sha256"]:
        raise VerificationError("release-clearance summary hash does not match payload")

    return {
        "status": "passed",
        "artifact_schema_version": manifest["artifact_schema_version"],
        "content_profile": manifest["content_profile"],
        "source_commit": manifest["source_commit"],
        "distribution_target": manifest["release_clearance"]["requested_target"],
        "distribution_status": manifest["release_clearance"]["status"],
        "outstanding_release_gates": manifest["release_clearance"][
            "outstanding_gates"
        ],
        "files_verified": len(expected_paths),
        "bytes_verified": bytes_verified,
        "strict": strict,
        "unlisted_files": extras,
    }


def main() -> int:
    default_root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "root",
        nargs="?",
        type=Path,
        default=default_root,
        help="extracted artifact root (default: parent of forensic-framework)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also reject every unlisted file; run immediately after extraction",
    )
    args = parser.parse_args()
    try:
        result = verify_artifact(args.root, strict=args.strict)
    except VerificationError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
