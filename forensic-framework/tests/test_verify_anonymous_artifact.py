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
    clearance_payload = root / verifier.RELEASE_CLEARANCE_PATH
    clearance_payload.parent.mkdir(parents=True)
    clearance_payload.write_text("{}\n")
    clearance_sha256 = hashlib.sha256(clearance_payload.read_bytes()).hexdigest()
    outstanding = [
        "code_license",
        "original_benchmark_license",
        "paper_release_terms",
        "endpoint_output_redistribution",
    ]
    manifest = {
        "artifact_schema_version": verifier.SUPPORTED_SCHEMA,
        "content_profile": "structured-output",
        "source_commit": "a" * 40,
        "identity_scan": {"status": "passed"},
        "include_raw_model_transcripts": False,
        "release_clearance": {
            "requested_target": "local-validation",
            "status": "local_validation_only_not_cleared_for_distribution",
            "approved_gates": [],
            "outstanding_gates": outstanding,
            "not_applicable_gates": [],
            "contains_structured_model_output": True,
            "path": verifier.RELEASE_CLEARANCE_PATH,
            "sha256": clearance_sha256,
            "endpoint_sha256": "e" * 64,
        },
        "aggregate_only_scan": None,
        "aggregate_run_files": None,
        "runs": {"synthetic": {"records_included": True}},
        "human_annotation_package_included": False,
        "human_adjudicated_analysis_included": False,
        "targeted_human_review_package_included": False,
        "files": [
            {
                "path": "payload/result.txt",
                "bytes": payload.stat().st_size,
                "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            },
            {
                "path": verifier.RELEASE_CLEARANCE_PATH,
                "bytes": clearance_payload.stat().st_size,
                "sha256": clearance_sha256,
            },
        ],
    }
    (root / verifier.MANIFEST_NAME).write_text(json.dumps(manifest))


def test_verify_artifact_checks_manifest_bound_payloads(tmp_path: Path) -> None:
    _write_artifact(tmp_path)
    result = verifier.verify_artifact(tmp_path, strict=True)
    assert result == {
        "status": "passed",
        "artifact_schema_version": verifier.SUPPORTED_SCHEMA,
        "content_profile": "structured-output",
        "source_commit": "a" * 40,
        "distribution_target": "local-validation",
        "distribution_status": (
            "local_validation_only_not_cleared_for_distribution"
        ),
        "outstanding_release_gates": [
            "code_license",
            "original_benchmark_license",
            "paper_release_terms",
            "endpoint_output_redistribution",
        ],
        "files_verified": 2,
        "bytes_verified": len("frozen result\n") + len("{}\n"),
        "strict": True,
        "unlisted_files": [],
    }


def test_verify_artifact_rejects_payload_tampering(tmp_path: Path) -> None:
    _write_artifact(tmp_path)
    (tmp_path / "payload" / "result.txt").write_text("changed result\n")
    with pytest.raises(verifier.VerificationError, match="size mismatch"):
        verifier.verify_artifact(tmp_path)


def test_verify_artifact_rejects_false_distribution_clearance(tmp_path: Path) -> None:
    _write_artifact(tmp_path)
    manifest_path = tmp_path / verifier.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["release_clearance"].update(
        {
            "requested_target": "anonymous-review",
            "status": "cleared_for_anonymous_review",
        }
    )
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(verifier.VerificationError, match="retains pending gates"):
        verifier.verify_artifact(tmp_path)


def test_verify_aggregate_profile_rejects_manifest_bound_records(
    tmp_path: Path,
) -> None:
    _write_artifact(tmp_path)
    records = tmp_path / "forensic-framework/data/warrant_runs/run/records.jsonl"
    records.parent.mkdir(parents=True)
    records.write_text("{}\n")
    manifest_path = tmp_path / verifier.MANIFEST_NAME
    manifest = json.loads(manifest_path.read_text())
    manifest["content_profile"] = "aggregate-only"
    manifest["release_clearance"].update(
        {
            "contains_structured_model_output": False,
            "outstanding_gates": [
                "code_license",
                "original_benchmark_license",
                "paper_release_terms",
            ],
            "not_applicable_gates": ["endpoint_output_redistribution"],
        }
    )
    manifest["aggregate_only_scan"] = {
        "status": "passed",
        "forbidden_path_scan": True,
        "fingerprint_width_words": verifier.OUTPUT_FINGERPRINT_WORDS,
        "verbatim_overlap_count": 0,
        "source_output_strings_fingerprinted": 10,
        "unique_output_fingerprints": 20,
        "release_files_scanned": 5,
    }
    manifest["aggregate_run_files"] = {
        "synthetic": [
            "analysis.json",
            "manifest.json",
            "release_redactions.json",
            "statistics.json",
        ]
    }
    manifest["runs"]["synthetic"]["records_included"] = False
    manifest["files"].append(
        {
            "path": "forensic-framework/data/warrant_runs/run/records.jsonl",
            "bytes": records.stat().st_size,
            "sha256": hashlib.sha256(records.read_bytes()).hexdigest(),
        }
    )
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(verifier.VerificationError, match="forbidden payload"):
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
    clearance_payload = tmp_path / verifier.RELEASE_CLEARANCE_PATH
    clearance_payload.parent.mkdir(parents=True)
    clearance_payload.write_text("{}\n")
    clearance_sha256 = hashlib.sha256(clearance_payload.read_bytes()).hexdigest()
    manifest = {
        "artifact_schema_version": verifier.SUPPORTED_SCHEMA,
        "content_profile": "structured-output",
        "source_commit": "a" * 40,
        "identity_scan": {"status": "passed"},
        "include_raw_model_transcripts": False,
        "release_clearance": {
            "requested_target": "local-validation",
            "status": "local_validation_only_not_cleared_for_distribution",
            "approved_gates": [],
            "outstanding_gates": [
                "code_license",
                "original_benchmark_license",
                "paper_release_terms",
                "endpoint_output_redistribution",
            ],
            "not_applicable_gates": [],
            "contains_structured_model_output": True,
            "path": verifier.RELEASE_CLEARANCE_PATH,
            "sha256": clearance_sha256,
            "endpoint_sha256": "e" * 64,
        },
        "aggregate_only_scan": None,
        "aggregate_run_files": None,
        "runs": {"synthetic": {"records_included": True}},
        "human_annotation_package_included": False,
        "human_adjudicated_analysis_included": False,
        "targeted_human_review_package_included": False,
        "files": [
            {
                "path": "payload/result.txt",
                "bytes": payload.stat().st_size,
                "sha256": hashlib.sha256(payload.read_bytes()).hexdigest(),
            },
            {
                "path": verifier.RELEASE_CLEARANCE_PATH,
                "bytes": clearance_payload.stat().st_size,
                "sha256": clearance_sha256,
            },
        ],
    }
    (tmp_path / verifier.MANIFEST_NAME).write_text(json.dumps(manifest))
    with pytest.raises(verifier.VerificationError, match="missing regular payload"):
        verifier.verify_artifact(tmp_path)
