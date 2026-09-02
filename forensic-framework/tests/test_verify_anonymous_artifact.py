from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import verify_anonymous_artifact as verifier


def _write_artifact(root: Path) -> None:
    payload = root / "payload" / "result.txt"
    payload.parent.mkdir(parents=True)
    payload.write_text("frozen result\n")
    manifest = {
        "artifact_schema_version": verifier.SUPPORTED_SCHEMA,
        "source_commit": "a" * 40,
        "identity_scan": {"status": "passed"},
        "files": [
            {
                "path": "payload/result.txt",
                "bytes": payload.stat().st_size,
                "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            }
        ],
    }
    (root / verifier.MANIFEST_NAME).write_text(json.dumps(manifest))


def test_verify_artifact_checks_manifest_bound_payloads(tmp_path: Path) -> None:
    _write_artifact(tmp_path)
    result = verifier.verify_artifact(tmp_path, strict=True)
    assert result == {
        "status": "passed",
        "artifact_schema_version": verifier.SUPPORTED_SCHEMA,
        "source_commit": "a" * 40,
        "files_verified": 1,
        "bytes_verified": len("frozen result\n"),
        "strict": True,
        "unlisted_files": [],
    }


def test_verify_artifact_rejects_payload_tampering(tmp_path: Path) -> None:
    _write_artifact(tmp_path)
    (tmp_path / "payload" / "result.txt").write_text("changed result\n")
    with pytest.raises(verifier.VerificationError, match="size mismatch"):
        verifier.verify_artifact(tmp_path)


@pytest.mark.parametrize(
    "unsafe",
    ["../outside.txt", "/absolute.txt", "a//b.txt", "..\\outside.txt"],
)
def test_verify_artifact_rejects_unsafe_manifest_paths(
    tmp_path: Path, unsafe: str
) -> None:
    _write_artifact(tmp_path)
    manifest_path = tmp_path / verifier.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["files"][0]["path"] = unsafe
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(verifier.VerificationError, match="unsafe|non-canonical"):
        verifier.verify_artifact(tmp_path)


def test_verify_artifact_strict_mode_rejects_unlisted_files(tmp_path: Path) -> None:
    _write_artifact(tmp_path)
    (tmp_path / "download-note.txt").write_text("not in the manifest\n")
    assert verifier.verify_artifact(tmp_path, strict=False)["status"] == "passed"
    with pytest.raises(verifier.VerificationError, match="unlisted files"):
        verifier.verify_artifact(tmp_path, strict=True)


def test_verify_artifact_rejects_symlinked_payload_parent(tmp_path: Path) -> None:
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "result.txt").write_text("frozen result\n")
    (tmp_path / "payload").symlink_to(outside, target_is_directory=True)
    payload = outside / "result.txt"
    manifest = {
        "artifact_schema_version": verifier.SUPPORTED_SCHEMA,
        "source_commit": "a" * 40,
        "identity_scan": {"status": "passed"},
        "files": [
            {
                "path": "payload/result.txt",
                "bytes": payload.stat().st_size,
                "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            }
        ],
    }
    (tmp_path / verifier.MANIFEST_NAME).write_text(json.dumps(manifest))
    with pytest.raises(verifier.VerificationError, match="missing regular payload"):
        verifier.verify_artifact(tmp_path)
