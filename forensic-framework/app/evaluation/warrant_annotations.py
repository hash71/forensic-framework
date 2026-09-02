"""Blinded, deterministic annotation-package export for warrant claims."""

from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ANNOTATION_EXPORT_VERSION = "warrant-annotation-export-v1.0"
ANNOTATION_AXES = (
    "citation",
    "actor",
    "action",
    "object",
    "temporal",
    "quantitative",
    "scope",
    "modality",
    "authorization",
    "intent",
    "causality",
    "decision",
)


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _jsonl_text(rows: list[dict[str, Any]]) -> str:
    return "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        for row in rows
    )


def build_annotation_items(
    records: list[dict[str, Any]],
    cases: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Deduplicate shared generations and separate blind/admin information."""

    sources: dict[tuple[str, str], dict[str, Any]] = {}
    conditions: dict[tuple[str, str], set[str]] = defaultdict(set)
    failures: list[dict[str, Any]] = []
    for record in records:
        generator = record.get("generator") or {}
        parsed = generator.get("parsed_output")
        response_hash = record.get("generator_response_sha256")
        if not parsed or not response_hash:
            failures.append({
                "run_id": record["run_id"],
                "case_id": record["case_id"],
                "condition": record["condition"],
                "repetition": record["repetition"],
                "operational_status": record["operational_status"],
                "parser_status": generator.get("parser_status"),
                "error_type": (generator.get("error") or {}).get("type"),
            })
            continue
        key = (record["case_id"], response_hash)
        sources.setdefault(key, record)
        conditions[key].add(record["condition"])

    blind_items: list[dict[str, Any]] = []
    admin_keys: list[dict[str, Any]] = []
    for (case_id, response_hash), record in sorted(sources.items()):
        case = cases[case_id]
        output = record["generator"]["parsed_output"]
        cited_index = {event["event_id"]: event for event in case["events"]}
        for claim in output["claims"]:
            annotation_id = "ann_" + _sha256(
                f"{ANNOTATION_EXPORT_VERSION}|{response_hash}|{claim['claim_id']}"
            )[:20]
            cited_events = [
                cited_index[event_id]
                for event_id in claim["cited_event_ids"]
                if event_id in cited_index
            ]
            blind_items.append({
                "annotation_export_version": ANNOTATION_EXPORT_VERSION,
                "annotation_id": annotation_id,
                "case_display_id": "case_" + _sha256(case_id)[:12],
                "visible_baselines": case["baselines"],
                "visible_events": case["events"],
                "claim": claim,
                "cited_events": cited_events,
                "investigation_context": {
                    "verdict": output["verdict"],
                    "suspect": output["suspect"],
                    "evidence_for": output["evidence_for"],
                    "evidence_against": output["evidence_against"],
                    "missing_evidence": output["missing_evidence"],
                },
            })
            admin_keys.append({
                "annotation_id": annotation_id,
                "run_id": record["run_id"],
                "requested_model": record["requested_model"],
                "case_id": case_id,
                "base_case_id": record["base_case_id"],
                "family": record["family"],
                "split": record["split"],
                "variant": record["variant"],
                "repetition": record["repetition"],
                "generation_group": record["generation_group"],
                "conditions_sharing_generation": sorted(conditions[(case_id, response_hash)]),
                "generator_response_sha256": response_hash,
                "claim_id": claim["claim_id"],
                "claim_type": claim["claim_type"],
                "generator_decisive": claim["decisive"],
                "expected_verdict": record["expected_verdict"],
            })

    order = {item["annotation_id"]: index for index, item in enumerate(blind_items)}
    admin_keys.sort(key=lambda item: order[item["annotation_id"]])
    return blind_items, admin_keys, failures


def select_stratified_ids(
    admin_keys: list[dict[str, Any]],
    *,
    sample_size: int,
    seed: int,
) -> set[str]:
    """Select a deterministic round-robin sample across material strata."""

    if sample_size >= len(admin_keys):
        return {item["annotation_id"] for item in admin_keys}
    strata: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for item in admin_keys:
        stratum = (
            item["expected_verdict"],
            item["generation_group"],
            item["claim_type"],
            item["generator_decisive"],
        )
        strata[stratum].append(item)
    for stratum, items in strata.items():
        items.sort(key=lambda item: _sha256(
            f"{seed}|{stratum}|{item['annotation_id']}"
        ))

    selected: set[str] = set()
    ordered_strata = sorted(strata, key=str)
    position = 0
    while len(selected) < sample_size:
        added = False
        for stratum in ordered_strata:
            items = strata[stratum]
            if position < len(items):
                selected.add(items[position]["annotation_id"])
                added = True
                if len(selected) == sample_size:
                    break
        if not added:
            break
        position += 1
    return selected


def _write_answer_template(path: Path, annotation_ids: list[str]) -> None:
    fields = [
        "annotation_id",
        "annotator_id",
        "overall_label",
        "materiality_decisive",
        *[f"axis_{axis}" for axis in ANNOTATION_AXES],
        "rationale",
        "missing_evidence",
        "adjudication_needed",
    ]
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for annotation_id in annotation_ids:
            writer.writerow({"annotation_id": annotation_id})


def export_annotation_package(
    records: list[dict[str, Any]],
    cases: dict[str, dict[str, Any]],
    output_dir: Path,
    *,
    sample_size: int,
    seed: int,
) -> dict[str, Any]:
    blind_items, admin_keys, failures = build_annotation_items(records, cases)
    selected_ids = select_stratified_ids(admin_keys, sample_size=sample_size, seed=seed)
    selected_blind = [
        item for item in blind_items if item["annotation_id"] in selected_ids
    ]
    selected_keys = [
        item for item in admin_keys if item["annotation_id"] in selected_ids
    ]

    blind_dir = output_dir / "blind"
    admin_dir = output_dir / "admin_do_not_share_with_annotators"
    blind_dir.mkdir(parents=True, exist_ok=True)
    admin_dir.mkdir(parents=True, exist_ok=True)
    items_text = _jsonl_text(selected_blind)
    key_text = _jsonl_text(selected_keys)
    failures_text = _jsonl_text(failures)
    (blind_dir / "items.jsonl").write_text(items_text)
    _write_answer_template(
        blind_dir / "annotator_1.csv",
        [item["annotation_id"] for item in selected_blind],
    )
    _write_answer_template(
        blind_dir / "annotator_2.csv",
        [item["annotation_id"] for item in selected_blind],
    )
    _write_answer_template(
        blind_dir / "adjudication.csv",
        [item["annotation_id"] for item in selected_blind],
    )
    (admin_dir / "key.jsonl").write_text(key_text)
    (admin_dir / "failures.jsonl").write_text(failures_text)

    manifest = {
        "annotation_export_version": ANNOTATION_EXPORT_VERSION,
        "seed": seed,
        "available_unique_claims": len(blind_items),
        "selected_claims": len(selected_blind),
        "generator_failures": len(failures),
        "items_sha256": _sha256(items_text),
        "admin_key_sha256": _sha256(key_text),
        "stratum_counts": dict(sorted(Counter(
            "|".join(map(str, (
                item["expected_verdict"],
                item["generation_group"],
                item["claim_type"],
                item["generator_decisive"],
            )))
            for item in selected_keys
        ).items())),
        "blinding_warning": (
            "Only the blind directory may be shared with annotators. The admin "
            "key reveals model, condition, family, and expected verdict."
        ),
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest
