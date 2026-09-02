"""Prepare label-honest external warrant cases from CERT r4.2 windows.

The CERT answer key labels whether a synthetic insider scenario occurred.  It
does *not* label which conclusions are warranted by a downsampled visible
window.  This adapter therefore retains the answer-key verdict only as a
``latent_incident_label`` evaluation target.  Mechanical claim-warrant scores
remain visible-record checks, and publications must not describe the binary
target as expert claim-level ground truth.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from app.ingestion.warrant_benchmark import PROJECT_ROOT


EXTERNAL_SCHEMA_VERSION = "warrant-external-cert-v1.0"
CERT_SCENARIOS_DIR = PROJECT_ROOT / "data" / "real_scenarios"
CERT_CASES_DIR = PROJECT_ROOT / "data" / "warrant_external"
CERT_CASES_PATH = CERT_CASES_DIR / "cert_r4_2_cases.jsonl"
CERT_MANIFEST_PATH = CERT_CASES_DIR / "cert_r4_2_manifest.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_ROOT))
    except ValueError:
        return str(path)


def _compact_cert_event(event: dict[str, Any]) -> dict[str, Any]:
    """Retain auditable fields while dropping synthetic text/context bloat."""

    compact = {
        key: event.get(key)
        for key in (
            "event_id",
            "timestamp",
            "source_type",
            "user",
            "action",
            "resource",
            "status",
        )
    }
    metadata = event.get("metadata") or {}
    compact_metadata: dict[str, Any] = {}
    if metadata.get("cert_event_type"):
        compact_metadata["cert_event_type"] = metadata["cert_event_type"]
    if metadata.get("pc"):
        compact_metadata["pc"] = metadata["pc"]
    if event.get("source_type") == "email":
        recipients = metadata.get("recipients") or []
        compact_metadata["recipient_count"] = len(recipients)
        if recipients:
            compact_metadata["first_recipient"] = recipients[0]
        if metadata.get("attachment_size_bytes") is not None:
            compact_metadata["attachment_size_bytes"] = metadata[
                "attachment_size_bytes"
            ]
        if metadata.get("attachments") is not None:
            compact_metadata["attachments"] = metadata["attachments"]
    if event.get("source_type") == "web_server" and compact.get("resource"):
        match = re.match(r"https?://([^/]+)", str(compact["resource"]))
        if match:
            compact["resource"] = f"http://{match.group(1)}"
    compact["metadata"] = compact_metadata
    return compact


def _window_user(scenario: dict[str, Any]) -> str:
    declared = scenario.get("ground_truth_user")
    observed = {
        str(event["user"])
        for event in scenario["events"]
        if event.get("user")
    }
    if declared:
        if observed and declared not in observed:
            raise ValueError(
                f"{scenario['scenario_id']}: declared user {declared} absent from window"
            )
        return str(declared)
    if len(observed) != 1:
        raise ValueError(
            f"{scenario['scenario_id']}: expected one observed user, found {sorted(observed)}"
        )
    return next(iter(observed))


def build_cert_warrant_case(scenario: dict[str, Any]) -> dict[str, Any]:
    """Convert one CERT user-month window without inventing warrant labels."""

    label = scenario["label"]
    if label not in {"ATTACK", "BENIGN"}:
        raise ValueError(f"{scenario['scenario_id']}: unsupported label {label}")
    user = _window_user(scenario)
    scenario_type = scenario.get("ground_truth_scenario_type")
    family = (
        f"cert_attack_type_{scenario_type or 'unknown'}"
        if label == "ATTACK"
        else "cert_benign_user_month"
    )
    events = [_compact_cert_event(event) for event in scenario["events"]]
    return {
        "external_schema_version": EXTERNAL_SCHEMA_VERSION,
        "case_id": scenario["scenario_id"],
        # Some malicious users contribute two months; cluster them together.
        "base_case_id": f"cert_user_{user}",
        "family": family,
        "split": "external",
        "variant": "observed_user_month",
        "source_dataset": "CERT Insider Threat Test Dataset r4.2",
        "baselines": {},
        "alerts": [],
        "events": events,
        "evaluation_target": {
            "verdict": "YES" if label == "ATTACK" else "NO",
            "suspect": user if label == "ATTACK" else None,
            "label_semantics": "latent_incident_label_not_visible_evidence_warrant",
        },
        "external_provenance": {
            "source_scenario_id": scenario["scenario_id"],
            "source_label": label,
            "source_user": user,
            "source_scenario_type": scenario_type,
            "month": scenario.get("month"),
            "downsampled": bool(scenario.get("downsampled")),
            "original_event_count": scenario.get("original_event_count"),
            "visible_event_count": len(events),
            "baseline_policy": "none_available",
            "alert_policy": "none_available",
            "label_warning": (
                "The CERT answer-key label describes the latent synthetic scenario; "
                "it is not an expert judgment that the downsampled visible events "
                "warrant a YES/NO conclusion or human attribution."
            ),
        },
    }


def load_cert_scenarios(
    scenarios_dir: Path = CERT_SCENARIOS_DIR,
) -> list[tuple[Path, dict[str, Any]]]:
    paths = sorted(scenarios_dir.glob("cert_*.json"))
    if not paths:
        raise FileNotFoundError(f"no CERT scenarios found under {scenarios_dir}")
    return [(path, json.loads(path.read_text())) for path in paths]


def prepare_cert_warrant_cases(
    *,
    scenarios_dir: Path = CERT_SCENARIOS_DIR,
    cases_path: Path = CERT_CASES_PATH,
    manifest_path: Path = CERT_MANIFEST_PATH,
) -> dict[str, Any]:
    """Write a deterministic compact JSONL benchmark and provenance manifest."""

    loaded = load_cert_scenarios(scenarios_dir)
    cases = [build_cert_warrant_case(scenario) for _, scenario in loaded]
    cases.sort(key=lambda case: case["case_id"])
    if len({case["case_id"] for case in cases}) != len(cases):
        raise ValueError("duplicate external case_id")

    cases_path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(case, sort_keys=True, separators=(",", ":")) + "\n"
        for case in cases
    )
    cases_path.write_text(payload)
    source_hashes = {
        _display_path(path): _sha256_bytes(path.read_bytes())
        for path, _ in loaded
    }
    manifest = {
        "external_schema_version": EXTERNAL_SCHEMA_VERSION,
        "source_dataset": "CERT Insider Threat Test Dataset r4.2",
        "source_doi": "10.1184/R1/12841247.v1",
        "source_license": "CC BY 4.0",
        "case_count": len(cases),
        "independent_user_cluster_count": len(
            {case["base_case_id"] for case in cases}
        ),
        "attack_window_count": sum(
            case["evaluation_target"]["verdict"] == "YES" for case in cases
        ),
        "benign_window_count": sum(
            case["evaluation_target"]["verdict"] == "NO" for case in cases
        ),
        "label_semantics": "latent_incident_label_not_visible_evidence_warrant",
        "cases_path": _display_path(cases_path),
        "cases_sha256": _sha256_bytes(payload.encode()),
        "source_file_sha256": source_hashes,
        "transform_policy": {
            "events": (
                "compact auditable fields; remove synthetic free text, long lists, "
                "derived severity, pseudo-IP, and inferred user-host-day session IDs"
            ),
            "baselines": "none available; empty mapping supplied",
            "alerts": "none available; empty list supplied",
            "clustering": "all windows for the same synthetic user share one base_case_id",
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def load_cert_warrant_cases(path: Path = CERT_CASES_PATH) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing; run prepare_cert_warrant_external.py first"
        )
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
