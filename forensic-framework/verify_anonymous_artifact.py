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
SUPPORTED_SCHEMA = "warrantlab-anonymous-artifact-v1.5"
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
    if not isinstance(outstanding, list) or not all(
        isinstance(item, str) for item in outstanding
    ):
        raise VerificationError("manifest has invalid outstanding release gates")
    if not isinstance(approved, list) or not all(
        isinstance(item, str) for item in approved
    ):
        raise VerificationError("manifest has invalid approved release gates")
    if (
        len(outstanding) != len(set(outstanding))
        or len(approved) != len(set(approved))
        or set(outstanding) & set(approved)
        or set(outstanding) | set(approved) != REQUIRED_RELEASE_GATES
    ):
        raise VerificationError("manifest release-gate partition is invalid")
    if target != "local-validation" and outstanding:
        raise VerificationError("distribution-cleared artifact retains pending gates")
    if clearance.get("contains_structured_model_output") is not True:
        raise VerificationError("manifest must record retained structured model output")
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
