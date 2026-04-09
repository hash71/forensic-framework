"""
Tests for app.rules.rule_engine — 16+ tests, 2 per rule (R001-R008).
"""

from app.rules.rule_engine import (
    check_unusual_ip,
    check_off_hours,
    check_privilege_escalation,
    check_bulk_download,
    check_cross_department,
    check_log_deletion,
    check_failed_login_spike,
    check_privilege_then_download,
    run_rules,
)


BASELINES = {
    "user_04": {
        "department": "finance",
        "role": "junior_accountant",
        "normal_hours": "09:00-17:00",
        "normal_ips": ["192.168.1.104"],
        "normal_directories": ["/data/finance/"],
    },
    "user_01": {
        "department": "finance",
        "role": "financial_analyst",
        "normal_hours": "08:30-18:00",
        "normal_ips": ["192.168.1.100"],
        "normal_directories": ["/data/finance/"],
    },
}


def _evt(event_id, timestamp, action, user="user_04", source_ip="185.220.101.34",
         source_type="auth", resource=None, status="success"):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_type": source_type,
        "user": user,
        "action": action,
        "resource": resource,
        "source_ip": source_ip,
        "status": status,
        "session_id": None,
        "severity": "info",
        "metadata": {},
    }


# ── R001: unusual_login_ip ───────────────────────────────────────────────────

def test_R001_triggers_on_unusual_ip():
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "login",
                   source_ip="185.220.101.34")]
    alerts = check_unusual_ip(events, BASELINES)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R001"
    assert "185.220.101.34" in alerts[0]["description"]


def test_R001_no_trigger_normal_ip():
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "login",
                   source_ip="192.168.1.104")]
    alerts = check_unusual_ip(events, BASELINES)
    assert len(alerts) == 0


# ── R002: off_hours_access ───────────────────────────────────────────────────

def test_R002_triggers_off_hours():
    events = [_evt("e1", "2026-04-01T02:47:00+06:00", "login")]
    alerts = check_off_hours(events, BASELINES)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R002"


def test_R002_no_trigger_normal_hours():
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "login")]
    alerts = check_off_hours(events, BASELINES)
    assert len(alerts) == 0


# ── R003: privilege_escalation ───────────────────────────────────────────────

def test_R003_triggers_privilege_change():
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "privilege_change",
                   source_type="admin", resource="role")]
    alerts = check_privilege_escalation(events, BASELINES)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R003"
    assert alerts[0]["severity"] == "critical"


def test_R003_no_trigger_no_change():
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "login")]
    alerts = check_privilege_escalation(events, BASELINES)
    assert len(alerts) == 0


# ── R004: bulk_download ──────────────────────────────────────────────────────

def test_R004_triggers_bulk_download():
    """More than 5 downloads within 30 minutes should trigger."""
    events = [
        _evt(f"e{i}", f"2026-04-01T03:{i:02d}:00+06:00", "file_download",
             source_type="file_access", resource=f"/data/file_{i}.csv")
        for i in range(1, 8)  # 7 downloads in 7 minutes
    ]
    alerts = check_bulk_download(events, BASELINES)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "R004"
    assert alerts[0]["severity"] == "critical"


def test_R004_no_trigger_few_downloads():
    """3 downloads should not trigger (threshold is >5)."""
    events = [
        _evt(f"e{i}", f"2026-04-01T03:{i:02d}:00+06:00", "file_download",
             source_type="file_access", resource=f"/data/file_{i}.csv")
        for i in range(1, 4)
    ]
    alerts = check_bulk_download(events, BASELINES)
    assert len(alerts) == 0


# ── R005: cross_department_access ────────────────────────────────────────────

def test_R005_triggers_cross_department():
    """user_04 (finance) accessing /data/hr/ should trigger."""
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "file_read",
                   source_type="file_access", resource="/data/hr/employee_records.csv")]
    alerts = check_cross_department(events, BASELINES)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R005"


def test_R005_no_trigger_own_department():
    """user_04 (finance) accessing /data/finance/ should NOT trigger."""
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "file_read",
                   source_type="file_access", resource="/data/finance/budget.xlsx")]
    alerts = check_cross_department(events, BASELINES)
    assert len(alerts) == 0


# ── R006: log_deletion ──────────────────────────────────────────────────────

def test_R006_triggers_log_delete():
    events = [_evt("e1", "2026-04-01T03:08:00+06:00", "log_delete",
                   source_type="admin", resource="/var/log/access.log")]
    alerts = check_log_deletion(events, BASELINES)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R006"
    assert alerts[0]["severity"] == "critical"


def test_R006_no_trigger_no_delete():
    events = [_evt("e1", "2026-04-01T10:00:00+06:00", "config_change",
                   source_type="admin")]
    alerts = check_log_deletion(events, BASELINES)
    assert len(alerts) == 0


# ── R007: failed_login_spike ────────────────────────────────────────────────

def test_R007_triggers_failed_spike():
    """Two failed logins within 5 minutes should trigger."""
    events = [
        _evt("e1", "2026-04-01T02:47:00+06:00", "login_failed", status="failure"),
        _evt("e2", "2026-04-01T02:48:00+06:00", "login_failed", status="failure"),
    ]
    alerts = check_failed_login_spike(events, BASELINES)
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "R007"


def test_R007_no_trigger_single_failure():
    """A single failed login should NOT trigger."""
    events = [
        _evt("e1", "2026-04-01T02:47:00+06:00", "login_failed", status="failure"),
    ]
    alerts = check_failed_login_spike(events, BASELINES)
    assert len(alerts) == 0


# ── R008: privilege_then_download ────────────────────────────────────────────

def test_R008_triggers_priv_then_download():
    """Privilege change followed by file_download within 30 min should trigger."""
    events = [
        _evt("e1", "2026-04-01T02:52:00+06:00", "privilege_change",
             source_type="admin", resource="role"),
        _evt("e2", "2026-04-01T02:55:00+06:00", "file_download",
             source_type="file_access", resource="/data/hr/records.csv"),
    ]
    alerts = check_privilege_then_download(events, BASELINES)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "R008"
    assert alerts[0]["severity"] == "critical"
    assert "e1" in alerts[0]["event_ids"]
    assert "e2" in alerts[0]["event_ids"]


def test_R008_no_trigger_download_only():
    """Downloads without a preceding privilege_change should NOT trigger."""
    events = [
        _evt("e1", "2026-04-01T02:55:00+06:00", "file_download",
             source_type="file_access", resource="/data/hr/records.csv"),
        _evt("e2", "2026-04-01T02:56:00+06:00", "file_download",
             source_type="file_access", resource="/data/hr/records2.csv"),
    ]
    alerts = check_privilege_then_download(events, BASELINES)
    assert len(alerts) == 0


# ── run_rules orchestration ─────────────────────────────────────────────────

def test_run_rules_returns_sorted_alerts():
    """run_rules should return alerts sorted by timestamp."""
    events = [
        _evt("e1", "2026-04-01T02:47:00+06:00", "login_failed", status="failure"),
        _evt("e2", "2026-04-01T02:48:00+06:00", "login_failed", status="failure"),
        _evt("e3", "2026-04-01T02:52:00+06:00", "privilege_change",
             source_type="admin", resource="role"),
    ]
    alerts = run_rules(events, BASELINES)
    assert len(alerts) > 0
    timestamps = [a["timestamp"] for a in alerts]
    assert timestamps == sorted(timestamps)


def test_run_rules_no_events_no_alerts():
    """Empty event list produces no alerts."""
    alerts = run_rules([], BASELINES)
    assert alerts == []
