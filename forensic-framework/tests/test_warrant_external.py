from __future__ import annotations

import json
from pathlib import Path

from app.ingestion.warrant_external import (
    build_cert_warrant_case,
    prepare_cert_warrant_cases,
)


def _scenario(*, scenario_id: str, label: str, user: str, month: str) -> dict:
    return {
        "scenario_id": scenario_id,
        "label": label,
        "ground_truth_user": user if label == "ATTACK" else None,
        "ground_truth_scenario_type": "2" if label == "ATTACK" else None,
        "month": month,
        "downsampled": True,
        "original_event_count": 900,
        "events": [
            {
                "event_id": f"{scenario_id}_evt_1",
                "timestamp": f"{month}-01T09:00:00+00:00",
                "source_type": "web_server",
                "user": user,
                "action": "http_request",
                "resource": "https://example.test/random/long/path?q=1",
                "source_ip": "pc:PC-1",
                "status": "200",
                "session_id": f"cert_{user}_PC-1_{month.replace('-', '')}01",
                "severity": "info",
                "metadata": {
                    "cert_event_type": "http",
                    "pc": "PC-1",
                    "cert_activity": "synthetic free text must not enter prompt",
                },
            }
        ],
    }


def test_build_cert_case_keeps_latent_label_semantics() -> None:
    case = build_cert_warrant_case(
        _scenario(
            scenario_id="cert_attack_ABC0001_201001",
            label="ATTACK",
            user="ABC0001",
            month="2010-01",
        )
    )
    assert case["evaluation_target"] == {
        "verdict": "YES",
        "suspect": "ABC0001",
        "label_semantics": "latent_incident_label_not_visible_evidence_warrant",
    }
    assert case["base_case_id"] == "cert_user_ABC0001"
    assert case["baselines"] == {}
    assert case["alerts"] == []
    assert case["events"][0]["resource"] == "http://example.test"
    assert "cert_activity" not in case["events"][0]["metadata"]
    assert "session_id" not in case["events"][0]
    assert "source_ip" not in case["events"][0]
    assert "severity" not in case["events"][0]


def test_benign_user_is_inferred_from_visible_events() -> None:
    case = build_cert_warrant_case(
        _scenario(
            scenario_id="cert_benign_DEF0002_201002",
            label="BENIGN",
            user="DEF0002",
            month="2010-02",
        )
    )
    assert case["evaluation_target"]["verdict"] == "NO"
    assert case["evaluation_target"]["suspect"] is None
    assert case["base_case_id"] == "cert_user_DEF0002"


def test_prepare_manifest_clusters_repeated_user_windows(tmp_path: Path) -> None:
    scenarios_dir = tmp_path / "scenarios"
    scenarios_dir.mkdir()
    scenarios = [
        _scenario(
            scenario_id="cert_attack_ABC0001_201001",
            label="ATTACK",
            user="ABC0001",
            month="2010-01",
        ),
        _scenario(
            scenario_id="cert_attack_ABC0001_201002",
            label="ATTACK",
            user="ABC0001",
            month="2010-02",
        ),
        _scenario(
            scenario_id="cert_benign_DEF0002_201001",
            label="BENIGN",
            user="DEF0002",
            month="2010-01",
        ),
    ]
    for scenario in scenarios:
        (scenarios_dir / f"{scenario['scenario_id']}.json").write_text(
            json.dumps(scenario)
        )
    cases_path = tmp_path / "cases.jsonl"
    manifest_path = tmp_path / "manifest.json"
    manifest = prepare_cert_warrant_cases(
        scenarios_dir=scenarios_dir,
        cases_path=cases_path,
        manifest_path=manifest_path,
    )
    assert manifest["case_count"] == 3
    assert manifest["independent_user_cluster_count"] == 2
    assert manifest["attack_window_count"] == 2
    assert manifest["benign_window_count"] == 1
    assert manifest["source_license"] == "CC BY 4.0"
    assert manifest["cases_sha256"]
    assert len(cases_path.read_text().splitlines()) == 3
