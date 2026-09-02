from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import prepare_warrant_annotations as preparation


def _write_manifest(run_dir: Path, benchmark: Path, digest: str | None = None) -> None:
    run_dir.mkdir()
    manifest = {
        "benchmark_path": benchmark.name,
        "benchmark_sha256": digest or hashlib.sha256(benchmark.read_bytes()).hexdigest(),
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest))


def test_resolve_cases_path_uses_and_authenticates_run_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    benchmark = tmp_path / "external_cases.jsonl"
    benchmark.write_text('{"case_id":"external_1"}\n')
    run_dir = tmp_path / "run"
    _write_manifest(run_dir, benchmark)
    monkeypatch.setattr(preparation, "PROJECT_ROOT", tmp_path)

    assert preparation.resolve_cases_path(run_dir) == benchmark


def test_resolve_cases_path_rejects_hash_mismatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    benchmark = tmp_path / "cases.jsonl"
    benchmark.write_text('{"case_id":"case_1"}\n')
    run_dir = tmp_path / "run"
    _write_manifest(run_dir, benchmark, digest="0" * 64)
    monkeypatch.setattr(preparation, "PROJECT_ROOT", tmp_path)

    with pytest.raises(ValueError, match="case-corpus hash mismatch"):
        preparation.resolve_cases_path(run_dir)
