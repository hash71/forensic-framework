#!/usr/bin/env python3
"""Redact workstation paths from a completed warrant run before Git release."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from app.ingestion.warrant_benchmark import PROJECT_ROOT


REDACTION_VERSION = "warrant-release-redaction-v1.0"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _default_replacements() -> list[tuple[str, str]]:
    return [
        (str(PROJECT_ROOT), "[PROJECT_ROOT]"),
        (str(PROJECT_ROOT.parent), "[MONOREPO_ROOT]"),
        (str(Path.home()), "[USER_HOME]"),
    ]


def sanitize_run_records(
    run_dir: Path,
    *,
    replacements: list[tuple[str, str]] | None = None,
) -> dict:
    """Redact path prefixes while retaining a local ignored original backup."""

    manifest_path = run_dir / "manifest.json"
    records_path = run_dir / "records.jsonl"
    raw_dir = run_dir / "raw"
    output_manifest = run_dir / "release_redactions.json"
    backup_path = run_dir / "records.private-original.jsonl"
    if not manifest_path.exists() or not records_path.exists():
        raise FileNotFoundError("completed run requires manifest.json and records.jsonl")
    if output_manifest.exists():
        prior = json.loads(output_manifest.read_text())
        if prior.get("redaction_version") != REDACTION_VERSION:
            raise ValueError("run has a different release-redaction version")
        if prior.get("post_redaction_records_sha256") != _sha256(records_path):
            raise ValueError("records changed after release redaction")
        return prior

    selected = sorted(
        replacements or _default_replacements(),
        key=lambda item: len(item[0]),
        reverse=True,
    )
    if any(not source or source == "/" for source, _ in selected):
        raise ValueError("unsafe redaction source")
    raw_hits = []
    if raw_dir.exists():
        for path in sorted(raw_dir.glob("*")):
            if not path.is_file():
                continue
            content = path.read_bytes()
            if any(source.encode() in content for source, _ in selected):
                raw_hits.append(path.name)
    if raw_hits:
        raise ValueError(
            "workstation path appears in raw model responses; release requires "
            f"a hash-preserving review strategy: {raw_hits[:5]}"
        )

    original_sha256 = _sha256(records_path)
    counts: dict[str, int] = {}
    allowed_fields = {"message", "traceback_tail"}

    def redact_value(value, *, field: str | None = None):
        if isinstance(value, dict):
            return {
                key: redact_value(item, field=key)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [redact_value(item, field=field) for item in value]
        if not isinstance(value, str):
            return value
        redacted = value
        for source, replacement in selected:
            count = redacted.count(source)
            if not count:
                continue
            if field not in allowed_fields:
                raise ValueError(
                    f"workstation path appears outside diagnostic field {field!r}"
                )
            redacted = redacted.replace(source, replacement)
            counts[replacement] = counts.get(replacement, 0) + count
        return redacted

    records = []
    for line_number, line in enumerate(records_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(redact_value(json.loads(line)))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid source JSON on line {line_number}") from exc
    text = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        for record in records
    )

    shutil.copyfile(records_path, backup_path)
    records_path.write_text(text)
    release_manifest = {
        "redaction_version": REDACTION_VERSION,
        "run_id": json.loads(manifest_path.read_text())["run_id"],
        "original_records_sha256": original_sha256,
        "post_redaction_records_sha256": _sha256(records_path),
        "replacement_counts": dict(sorted(counts.items())),
        "redacted_fields_policy": (
            "literal workstation-root prefixes in diagnostic strings only; "
            "model responses, predictions, labels, prompts, and hashes unchanged"
        ),
        "private_original_backup": backup_path.name,
        "private_original_backup_sha256": _sha256(backup_path),
        "private_original_backup_git_ignored": True,
    }
    output_manifest.write_text(
        json.dumps(release_manifest, indent=2, sort_keys=True) + "\n"
    )
    return release_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    manifest = sanitize_run_records(args.run_dir)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
