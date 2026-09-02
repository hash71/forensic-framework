from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest
from reportlab.pdfgen import canvas

import build_anonymous_artifact as artifact


def _write_complete_run(run_dir: Path) -> None:
    run_dir.mkdir()
    records = '{"case_id":"case-1"}\n'
    (run_dir / "records.jsonl").write_text(records)
    (run_dir / "manifest.json").write_text(
        json.dumps(
            {
                "run_id": "complete-run",
                "counts_for_this_invocation": {
                    "planned": 1,
                    "completed": 1,
                },
            }
        )
    )
    (run_dir / "release_redactions.json").write_text(
        json.dumps(
            {
                "run_id": "complete-run",
                "post_redaction_records_sha256": hashlib.sha256(records.encode()).hexdigest(),
            }
        )
    )


def test_validate_release_run_checks_completion_and_public_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact, "REPO_ROOT", tmp_path)
    run_dir = tmp_path / "run"
    _write_complete_run(run_dir)
    summary = artifact.validate_release_run(run_dir)
    assert summary["record_count"] == 1
    (run_dir / "records.jsonl").write_text('{"case_id":"changed"}\n')
    with pytest.raises(ValueError, match="release_redactions"):
        artifact.validate_release_run(run_dir)


def test_release_scan_detects_identity_path_and_credential(tmp_path):
    (tmp_path / "clean.txt").write_text("Anonymous research artifact")
    assert artifact.scan_release_tree(tmp_path, identity_terms=["private-author"]) == []
    (tmp_path / "leak.txt").write_text(
        "private-author at /" + "Users/private-author/work with token ghp_" + "A" * 30
    )
    rules = {
        item["rule"]
        for item in artifact.scan_release_tree(tmp_path, identity_terms=["private-author"])
    }
    assert "identity_term_1" in rules
    assert "absolute_user_path" in rules
    assert "credential_like_value" in rules


def test_release_scan_extracts_pdf_text_and_metadata(tmp_path):
    pdf_path = tmp_path / "paper.pdf"
    pdf = canvas.Canvas(str(pdf_path))
    pdf.setAuthor("private-author")
    pdf.drawString(72, 720, "Anonymous body")
    pdf.save()
    issues = artifact.scan_release_tree(tmp_path, identity_terms=["private-author"])
    assert {item["rule"] for item in issues} == {"identity_term_1"}


def test_files_in_tree_excludes_private_backups(tmp_path, monkeypatch):
    monkeypatch.setattr(artifact, "REPO_ROOT", tmp_path)
    source = tmp_path / "source"
    source.mkdir()
    (source / "records.jsonl").write_text("{}\n")
    (source / "records.private-original.jsonl").write_text("private\n")
    (source / ".env").write_text("SECRET=value\n")
    assert [path.name for path in artifact.files_in_tree(source)] == ["records.jsonl"]


def test_zip_writer_is_deterministic(tmp_path):
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "b.txt").write_text("second")
    (staging / "a.txt").write_text("first")
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    artifact._write_zip(staging, first)
    artifact._write_zip(staging, second)
    assert first.read_bytes() == second.read_bytes()
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == ["a.txt", "b.txt"]
