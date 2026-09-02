from __future__ import annotations

import hashlib
import json
import subprocess
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


def test_confidence_audit_must_bind_both_runs_and_forbid_test_tuning(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(artifact, "REPO_ROOT", tmp_path)
    audit_path = tmp_path / "confidence_audit.json"
    audit = {
        "confidence_audit_schema_version": "warrant-confidence-audit-v1.1",
        "source_sha256": {
            "development_records": "d" * 64,
            "test_records": "t" * 64,
            "development_manifest": "m" * 64,
            "test_manifest": "n" * 64,
        },
        "benchmark_alignment": {
            "development_benchmark_sha256": "a" * 64,
            "test_benchmark_sha256": "b" * 64,
        },
        "calibrator_fit_decision": {
            "status": "not_fit",
            "threshold_selected": None,
        },
        "held_out_use_boundary": (
            "No calibrator or replacement threshold was selected from test labels."
        ),
    }
    audit_path.write_text(json.dumps(audit))

    summary = artifact.validate_confidence_audit(
        audit_path,
        development_records_sha256="d" * 64,
        test_records_sha256="t" * 64,
        development_manifest_sha256="m" * 64,
        test_manifest_sha256="n" * 64,
        development_benchmark_sha256="a" * 64,
        test_benchmark_sha256="b" * 64,
    )
    assert summary["calibrator_fit_status"] == "not_fit"

    audit["calibrator_fit_decision"]["threshold_selected"] = 0.90
    audit_path.write_text(json.dumps(audit))
    with pytest.raises(ValueError, match="must not tune"):
        artifact.validate_confidence_audit(
            audit_path,
            development_records_sha256="d" * 64,
            test_records_sha256="t" * 64,
            development_manifest_sha256="m" * 64,
            test_manifest_sha256="n" * 64,
            development_benchmark_sha256="a" * 64,
            test_benchmark_sha256="b" * 64,
        )


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


def test_release_scan_rejects_generated_bytecode(tmp_path):
    cache = tmp_path / "package" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "module.cpython-311.pyc").write_bytes(b"bytecode")
    assert artifact.scan_release_tree(tmp_path, identity_terms=[]) == [
        {
            "file": "package/__pycache__/module.cpython-311.pyc",
            "rule": "generated_cache_file",
        }
    ]


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


def test_omitted_raw_staging_normalizes_analyses_and_paper_derivatives(
    tmp_path, monkeypatch
):
    staging = tmp_path / "staging"
    framework = staging / "forensic-framework"
    paper = staging / "conference_paper"
    framework.mkdir(parents=True)
    paper.mkdir()
    (paper / "generate_paper_artifacts.py").write_text("# staged generator\n")
    runs = {
        "development": {
            "path": "forensic-framework/data/warrant_runs/development"
        },
        "synthetic_confirmatory": {
            "path": "forensic-framework/data/warrant_runs/synthetic"
        },
        "external_transfer": {
            "path": "forensic-framework/data/warrant_runs/external"
        },
    }
    for run in runs.values():
        (staging / run["path"]).mkdir(parents=True)
    (staging / "simulated-ai-review").mkdir()
    (staging / "simulated-ai-review" / "analysis.json").write_text("{}\n")

    calls = []

    def fake_run(args, *, cwd):
        calls.append((args, cwd))
        if Path(args[1]).name == "run_warrant_results.py":
            run_path = Path(args[2])
            (run_path / "analysis.json").write_text(
                json.dumps(
                    {
                        "artifact_integrity": {
                            "ok": True,
                            "raw_response_status": "omitted_by_release_policy",
                            "unique_raw_responses_referenced": 3,
                            "unique_raw_responses_checked": 0,
                            "unique_raw_responses_missing": 3,
                        }
                    }
                )
            )

    monkeypatch.setattr(artifact, "_run_staged", fake_run)
    artifact._normalize_omitted_raw_derivatives(
        staging,
        run_summaries=runs,
        has_human_analysis=False,
        has_simulated_analysis=True,
    )

    result_calls = [args for args, _ in calls[:-1]]
    assert len(result_calls) == 3
    assert all(args[-1] == "--allow-omitted-raw" for args in result_calls)
    generator_args, generator_cwd = calls[-1]
    assert Path(generator_args[1]).name == "generate_paper_artifacts.py"
    assert "--confidence-audit" in generator_args
    assert "--external-run-dir" in generator_args
    assert "--simulated-analysis" in generator_args
    assert generator_cwd == staging


def test_run_staged_surfaces_derivation_failure(tmp_path, monkeypatch):
    failed = subprocess.CompletedProcess(
        ["python", "derive.py"],
        returncode=2,
        stdout="",
        stderr="invalid staged input",
    )
    observed = {}

    def fake_subprocess_run(*args, **kwargs):
        observed.update(kwargs)
        return failed

    monkeypatch.setattr(artifact.subprocess, "run", fake_subprocess_run)
    with pytest.raises(ValueError, match="invalid staged input"):
        artifact._run_staged(["python", "derive.py"], cwd=tmp_path)
    assert observed["env"]["PYTHONDONTWRITEBYTECODE"] == "1"


def test_readme_distinguishes_unfilled_package_from_human_analysis(tmp_path):
    readme = tmp_path / "README.md"
    runs = {
        "development": {
            "path": "forensic-framework/data/warrant_runs/development"
        },
        "synthetic_confirmatory": {
            "path": "forensic-framework/data/warrant_runs/synthetic"
        },
        "external_transfer": {
            "path": "forensic-framework/data/warrant_runs/external"
        },
    }

    artifact._write_readme(
        readme,
        include_raw=False,
        has_human_package=True,
        has_human_analysis=False,
        run_summaries=runs,
        has_simulated_analysis=True,
    )
    text = readme.read_text()
    assert "--allow-omitted-raw" in text
    assert "--development-run-dir data/warrant_runs/development" in text
    assert "no adjudicated expert analysis exists" in text
    assert "byte-stable under the reproduction command" in text
    assert "does not call Gemma or any remote endpoint" in text
    assert "About 1 GB of free disk" in text
    assert "verify_anonymous_artifact.py --strict ." in text
    assert "does not authenticate the ZIP itself" in text
    assert "--human-analysis" not in text
    assert "--simulated-analysis ../simulated-ai-review/analysis.json" in text
    assert "not human or expert validation" in text

    artifact._write_readme(
        readme,
        include_raw=False,
        has_human_package=True,
        has_human_analysis=True,
        run_summaries=runs,
    )
    text = readme.read_text()
    assert "--human-analysis ../human-validation/adjudicated_analysis.json" in text
    assert "checksum-bound adjudicated expert analysis" in text
