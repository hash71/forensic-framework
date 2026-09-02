from __future__ import annotations

import json
from pathlib import Path

from app.ingestion.warrant_benchmark import PROJECT_ROOT
from app.llm.warrant_runner import _safe_error
from sanitize_warrant_release import sanitize_run_records


def test_release_redaction_retains_ignored_original_and_is_idempotent(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "manifest.json").write_text(json.dumps({"run_id": "run_1"}))
    records = (
        json.dumps({
            "run_id": "run_1",
            "error": {"traceback_tail": 'File "/' + "Users/example/project/app.py\""},
        })
        + "\n"
    )
    (run_dir / "records.jsonl").write_text(records)

    manifest = sanitize_run_records(
        run_dir, replacements=[("/" + "Users/example", "[USER_HOME]")]
    )
    repeated = sanitize_run_records(
        run_dir, replacements=[("/" + "Users/example", "[USER_HOME]")]
    )

    assert manifest == repeated
    assert manifest["replacement_counts"] == {"[USER_HOME]": 1}
    assert "[USER_HOME]/project/app.py" in (run_dir / "records.jsonl").read_text()
    assert (run_dir / "records.private-original.jsonl").read_text() == records


def test_runner_error_payload_redacts_workstation_paths() -> None:
    payload = _safe_error(ValueError(f"failed under {PROJECT_ROOT}/private.py"))

    assert str(Path.home()) not in json.dumps(payload)
    assert "[PROJECT_ROOT]/private.py" in payload["message"]
