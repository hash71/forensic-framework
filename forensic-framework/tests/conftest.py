"""
Shared fixtures for the forensic framework test suite.
"""

import json
import sys
from pathlib import Path

import pytest

# Ensure project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def sample_baselines():
    """Load real user baselines from data/user_baselines.json."""
    baselines_path = PROJECT_ROOT / "data" / "user_baselines.json"
    with open(baselines_path, "r") as f:
        return json.load(f)


@pytest.fixture
def sample_auth_event():
    """A single raw auth event dict."""
    return {
        "timestamp": "2026-04-01T10:00:00+06:00",
        "event_type": "login",
        "username": "user_01",
        "ip_address": "192.168.1.100",
        "result": "success",
        "session": "sess_user_01_20260401_001",
    }


@pytest.fixture
def sample_file_event():
    """A single raw file event dict."""
    return {
        "timestamp": "2026-04-01T10:30:00+06:00",
        "event_type": "file_download",
        "username": "user_01",
        "file_path": "/data/finance/report_q1.xlsx",
        "file_size_bytes": 245000,
        "ip_address": "192.168.1.100",
        "result": "success",
        "session": "sess_user_01_20260401_001",
    }


@pytest.fixture
def sample_admin_event():
    """A single raw admin event dict."""
    return {
        "timestamp": "2026-04-01T11:00:00+06:00",
        "event_type": "privilege_change",
        "username": "user_04",
        "target": "role",
        "detail": "Changed role from read_only to admin",
        "ip_address": "185.220.101.34",
        "result": "success",
    }


@pytest.fixture
def sample_normalized_events():
    """List of 5 normalized events for testing rules."""
    return [
        {
            "event_id": "evt_s0_001",
            "timestamp": "2026-04-01T02:47:00+06:00",
            "source_type": "auth",
            "user": "user_04",
            "action": "login_failed",
            "resource": None,
            "source_ip": "185.220.101.34",
            "status": "failure",
            "session_id": None,
            "severity": "warning",
            "metadata": {},
        },
        {
            "event_id": "evt_s0_002",
            "timestamp": "2026-04-01T02:49:00+06:00",
            "source_type": "auth",
            "user": "user_04",
            "action": "login",
            "resource": None,
            "source_ip": "185.220.101.34",
            "status": "success",
            "session_id": "sess_compromised",
            "severity": "info",
            "metadata": {},
        },
        {
            "event_id": "evt_s0_003",
            "timestamp": "2026-04-01T02:52:00+06:00",
            "source_type": "admin",
            "user": "user_04",
            "action": "privilege_change",
            "resource": "role",
            "source_ip": "185.220.101.34",
            "status": "success",
            "session_id": None,
            "severity": "warning",
            "metadata": {"detail": "Changed role from read_only to admin"},
        },
        {
            "event_id": "evt_s0_004",
            "timestamp": "2026-04-01T02:55:00+06:00",
            "source_type": "file_access",
            "user": "user_04",
            "action": "file_download",
            "resource": "/data/hr/employee_records.csv",
            "source_ip": "185.220.101.34",
            "status": "success",
            "session_id": "sess_compromised",
            "severity": "info",
            "metadata": {"file_size_bytes": 500000},
        },
        {
            "event_id": "evt_s0_005",
            "timestamp": "2026-04-01T03:08:00+06:00",
            "source_type": "admin",
            "user": "user_04",
            "action": "log_delete",
            "resource": "/var/log/file_access.log",
            "source_ip": "185.220.101.34",
            "status": "success",
            "session_id": None,
            "severity": "critical",
            "metadata": {},
        },
    ]


@pytest.fixture
def sample_llm_response_attack():
    """Mock LLM response describing an attack chain with valid event_ids."""
    return {
        "verdict": "YES",
        "confidence": "HIGH",
        "suspect": "user_04",
        "narrative": "An attacker used compromised user_04 credentials (evt_s0_001) to gain access.",
        "attack_chain": [
            {"step": 1, "event_id": "evt_s0_001", "description": "Failed login attempts from unusual IP"},
            {"step": 2, "event_id": "evt_s0_002", "description": "Successful login from Tor exit node"},
            {"step": 3, "event_id": "evt_s0_003", "description": "Privilege escalation to admin"},
            {"step": 4, "event_id": "evt_s0_004", "description": "Bulk file download of HR records"},
            {"step": 5, "event_id": "evt_s0_005", "description": "Log deletion to cover tracks"},
        ],
        "evidence_for": ["evt_s0_001", "evt_s0_003", "evt_s0_005"],
        "evidence_against": [],
    }


@pytest.fixture
def sample_llm_response_benign():
    """Mock LLM response with NO verdict (benign assessment)."""
    return {
        "verdict": "NO",
        "confidence": "HIGH",
        "suspect": None,
        "narrative": "All observed activity is consistent with normal user behaviour.",
        "attack_chain": [],
        "evidence_for": [],
        "evidence_against": [],
    }


@pytest.fixture
def sample_llm_response_hallucinated():
    """Mock LLM response that references fake event_ids."""
    return {
        "verdict": "YES",
        "confidence": "MEDIUM",
        "suspect": "user_99",
        "narrative": "Suspicious activity detected involving evt_s99_001.",
        "attack_chain": [
            {"step": 1, "event_id": "evt_s99_001", "description": "Unauthorized access"},
            {"step": 2, "event_id": "evt_s0_002", "description": "Lateral movement"},
            {"step": 3, "description": "Data exfiltration without evidence"},
        ],
        "evidence_for": ["evt_s99_001", "evt_s0_002"],
        "evidence_against": ["evt_s99_002"],
    }
