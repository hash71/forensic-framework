"""DARPA OpTC (Operationally Transparent Cyber) adapter skeleton.

Source dataset:
    https://github.com/FiveDirections/OpTC-data

OpTC is large (~17 TB uncompressed across ecar-bro / ecar-twosix / ecar-mt
buckets) and packaged as zstd-compressed JSON-line files. Unlike LANL it
does NOT distribute red-team labels in a single file; ground truth lives
in the published red-team daily plan ("Red-Team Ground Truth", Schedule A
PDF). For that reason this module is a SKELETON: it documents the field
mapping and provides parsing primitives, but it does not synthesize ground
truth and will not fabricate scenarios from incomplete inputs.

Field mapping notes (ecar-twosix host telemetry → unified event):

    OpTC field                          Unified field
    ---------------------------------   ----------------------------------
    timestamp                           timestamp  (already ISO)
    actorID / principal                 user
    objectID / object_path              resource
    object                              source_type:
        FILE  -> file_access            "file_access"
        FLOW  -> network                "network"
        PROCESS -> admin (process exec) "admin"
        REGISTRY -> admin (config)      "admin"
        MODULE -> admin                 "admin"
    action                              action     (CREATE, READ, WRITE, MODIFY,
                                                     OPEN, START, TERMINATE, ...)
    hostName                            source_ip  ("host:<hostName>")

To map OpTC properly the analyst needs:
    1. The Red-Team Ground Truth PDF (Schedule A) — manual extraction.
    2. ecar-twosix host telemetry for the hosts in scope.
    3. A scenario-windowing scheme analogous to LANL.

Until those inputs are in place, calling `load_scenarios` raises
`NotImplementedError` to prevent silent fabrication of evaluation data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator


# ---------------------------------------------------------------------------
# Primitives (safe to expose; do not synthesize ground truth)
# ---------------------------------------------------------------------------

_OBJECT_TO_SOURCE_TYPE = {
    "FILE": "file_access",
    "FLOW": "network",
    "PROCESS": "admin",
    "REGISTRY": "admin",
    "MODULE": "admin",
    "SHELL": "admin",
}


def iter_ecar_jsonl(path: Path) -> Iterator[dict]:
    """Yield raw OpTC ecar records from a JSONL file (one JSON per line).

    The ecar-twosix bucket distributes records as one JSON object per line,
    optionally zstd-compressed. This helper only handles plain JSONL; for
    .zst files use a streaming decoder (e.g. zstandard.ZstdDecompressor)
    upstream.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def to_unified(record: dict, idx: int) -> dict | None:
    """Map a single OpTC ecar record to the unified event schema.

    Returns None for records of unmapped types (so callers can filter).
    """
    obj_type = record.get("object")
    source_type = _OBJECT_TO_SOURCE_TYPE.get(obj_type)
    if source_type is None:
        return None

    return {
        "event_id": f"optc_{idx:08d}",
        "timestamp": record.get("timestamp"),
        "source_type": source_type,
        "user": record.get("principal") or record.get("actorID"),
        "action": str(record.get("action", "")).lower(),
        "resource": record.get("objectID") or
                     record.get("properties", {}).get("file_path") or
                     record.get("properties", {}).get("image_path"),
        "source_ip": f"host:{record.get('hostName')}",
        "status": "success",
        "session_id": record.get("processID"),
        "severity": "info",
        "metadata": {
            "optc_object": obj_type,
            "optc_action": record.get("action"),
            "properties": record.get("properties", {}),
        },
    }


def load_scenarios(*args, **kwargs):
    """Not implemented. See module docstring."""
    raise NotImplementedError(
        "OpTC adapter is a skeleton. Ground-truth windowing depends on the "
        "Red-Team Ground Truth PDF; see app/ingestion/adapters/optc.py "
        "docstring for the required inputs."
    )
