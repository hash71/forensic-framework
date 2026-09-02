from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import reproduce_warrant_paper as reproduction


def _write_complete_run(root: Path) -> Path:
    benchmark = root / "benchmark.jsonl"
    benchmark.write_text('{"case":"c1"}\n')
    run_dir = root / "run"
    run_dir.mkdir()
    records = [
        {
            "run_id": "run_1",
            "case_id": "c1",
            "condition": condition,
            "repetition": 0,
        }
        for condition in ("a", "b")
    ]
    (run_dir / "records.jsonl").write_text(
        "".join(json.dumps(record) + "\n" for record in records)
    )
    manifest = {
        "run_id": "run_1",
        "case_count": 1,
        "conditions": ["a", "b"],
        "repetitions": 1,
        "benchmark_path": "benchmark.jsonl",
        "benchmark_sha256": hashlib.sha256(benchmark.read_bytes()).hexdigest(),
        "git_commit": "abc123",
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))
    return run_dir


def test_verify_complete_run_checks_cardinality_and_benchmark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reproduction, "PROJECT_ROOT", tmp_path)
    run_dir = _write_complete_run(tmp_path)

    verified = reproduction.verify_complete_run(run_dir)

    assert verified["record_count"] == 2
    assert verified["git_commit"] == "abc123"


def test_verify_complete_run_rejects_duplicate_record_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reproduction, "PROJECT_ROOT", tmp_path)
    run_dir = _write_complete_run(tmp_path)
    first = (run_dir / "records.jsonl").read_text().splitlines()[0]
    (run_dir / "records.jsonl").write_text(first + "\n" + first + "\n")

    with pytest.raises(ValueError, match="unique records"):
        reproduction.verify_complete_run(run_dir)


def test_verify_complete_run_checks_release_record_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reproduction, "PROJECT_ROOT", tmp_path)
    run_dir = _write_complete_run(tmp_path)
    records = run_dir / "records.jsonl"
    (run_dir / "release_redactions.json").write_text(
        json.dumps(
            {
                "run_id": "run_1",
                "post_redaction_records_sha256": hashlib.sha256(
                    records.read_bytes()
                ).hexdigest(),
            }
        )
    )

    verified = reproduction.verify_complete_run(run_dir)
    assert verified["release_records_sha256_verified"] is True

    records.write_text(records.read_text() + "\n")
    with pytest.raises(ValueError, match="release-record hash mismatch"):
        reproduction.verify_complete_run(run_dir)


def test_ensure_paper_build_dir_supports_fresh_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paper_dir = tmp_path / "conference_paper"
    monkeypatch.setattr(reproduction, "PAPER_DIR", paper_dir)

    build_dir = reproduction.ensure_paper_build_dir()

    assert build_dir == paper_dir / "build"
    assert build_dir.is_dir()


def test_simulated_analysis_requires_non_expert_boundary_and_record_binding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reproduction, "PROJECT_ROOT", tmp_path)
    run_dir = _write_complete_run(tmp_path)
    records_hash = hashlib.sha256((run_dir / "records.jsonl").read_bytes()).hexdigest()
    analysis = {
        "validity_boundary": "AI sensitivity study; not expert validation",
        "source_sha256": {"records": records_hash},
    }
    path = tmp_path / "simulated.json"
    path.write_text(json.dumps(analysis))
    verified = reproduction.verify_complete_run(run_dir)
    assert analysis["source_sha256"]["records"] == verified["records_sha256"]
