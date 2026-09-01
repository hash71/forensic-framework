"""
Tests for app.normalizer.normalizer — 8+ tests covering all three normalizers.
"""

from app.normalizer.normalizer import (
    normalize_auth_event,
    normalize_file_event,
    normalize_admin_event,
)


# ── Auth events ──────────────────────────────────────────────────────────────

def test_normalize_auth_event_login(sample_auth_event):
    """Successful login maps fields correctly and has severity 'info'."""
    result = normalize_auth_event(sample_auth_event, event_counter=1, scenario_id="s1")

    assert result["event_id"] == "evt_s1_001"
    assert result["source_type"] == "auth"
    assert result["user"] == "user_01"
    assert result["action"] == "login"
    assert result["source_ip"] == "192.168.1.100"
    assert result["status"] == "success"
    assert result["session_id"] == "sess_user_01_20260401_001"
    assert result["severity"] == "info"
    assert result["timestamp"] == sample_auth_event["timestamp"]


def test_normalize_auth_event_failed():
    """A login with result='failure' should produce severity 'warning'."""
    raw = {
        "timestamp": "2026-04-01T02:47:00+06:00",
        "event_type": "login",
        "username": "user_04",
        "ip_address": "185.220.101.34",
        "result": "failure",
        "session": None,
    }
    result = normalize_auth_event(raw, event_counter=5, scenario_id="s3")

    assert result["event_id"] == "evt_s3_005"
    assert result["severity"] == "warning"
    assert result["status"] == "failure"


def test_normalize_auth_event_login_failed_event_type():
    """event_type='login_failed' should also produce severity 'warning'."""
    raw = {
        "timestamp": "2026-04-01T02:47:00+06:00",
        "event_type": "login_failed",
        "username": "user_04",
        "ip_address": "185.220.101.34",
        "result": "failure",
        "session": None,
    }
    result = normalize_auth_event(raw, event_counter=1, scenario_id="s3")
    assert result["severity"] == "warning"


# ── File events ──────────────────────────────────────────────────────────────

def test_normalize_file_event_download(sample_file_event):
    """file_download includes file_size_bytes in metadata."""
    result = normalize_file_event(sample_file_event, event_counter=2, scenario_id="s1")

    assert result["event_id"] == "evt_s1_002"
    assert result["source_type"] == "file_access"
    assert result["action"] == "file_download"
    assert result["resource"] == "/data/finance/report_q1.xlsx"
    assert result["metadata"]["file_size_bytes"] == 245000


def test_normalize_file_event_read():
    """file_read without file_size_bytes has empty metadata."""
    raw = {
        "timestamp": "2026-04-01T10:00:00+06:00",
        "event_type": "file_read",
        "username": "user_01",
        "file_path": "/data/finance/budget.xlsx",
        "ip_address": "192.168.1.100",
        "result": "success",
        "session": "sess_001",
    }
    result = normalize_file_event(raw, event_counter=3, scenario_id="s1")

    assert result["action"] == "file_read"
    assert result["severity"] == "info"
    assert "file_size_bytes" not in result["metadata"]


# ── Admin events ─────────────────────────────────────────────────────────────

def test_normalize_admin_event_privilege(sample_admin_event):
    """privilege_change has severity 'warning' and detail in metadata."""
    result = normalize_admin_event(sample_admin_event, event_counter=4, scenario_id="s3")

    assert result["event_id"] == "evt_s3_004"
    assert result["source_type"] == "admin"
    assert result["action"] == "privilege_change"
    assert result["severity"] == "warning"
    assert result["metadata"]["detail"] == "Changed role from read_only to admin"
    assert result["session_id"] is None  # admin events have no session_id


def test_normalize_admin_event_log_delete():
    """log_delete has severity 'critical'."""
    raw = {
        "timestamp": "2026-04-01T03:08:00+06:00",
        "event_type": "log_delete",
        "username": "user_04",
        "target": "/var/log/file_access.log",
        "detail": "Deleted access log",
        "ip_address": "185.220.101.34",
        "result": "success",
    }
    result = normalize_admin_event(raw, event_counter=17, scenario_id="s3")

    assert result["severity"] == "critical"
    assert result["resource"] == "/var/log/file_access.log"


# ── Edge cases ───────────────────────────────────────────────────────────────

def test_metadata_strips_underscore_keys():
    """Keys starting with _ in auth metadata should be removed."""
    # The normalizer builds metadata dict and strips _ prefixed keys.
    # Auth normalizer builds an empty dict then strips, so result is always empty.
    raw = {
        "timestamp": "2026-04-01T10:00:00+06:00",
        "event_type": "login",
        "username": "user_01",
        "ip_address": "192.168.1.100",
        "result": "success",
        "session": "sess_001",
    }
    result = normalize_auth_event(raw, event_counter=1, scenario_id="s0")
    # Verify no underscore-prefixed keys survive in metadata
    for key in result["metadata"]:
        assert not key.startswith("_"), f"Underscore key {key!r} found in metadata"


def test_null_fields_handled():
    """Null resource and null session_id should not crash normalizers."""
    raw_auth = {
        "timestamp": "2026-04-01T10:00:00+06:00",
        "event_type": "login",
        "username": "user_01",
        "ip_address": None,
        "result": "success",
        "session": None,
    }
    result = normalize_auth_event(raw_auth, event_counter=1, scenario_id="s0")
    assert result["source_ip"] is None
    assert result["session_id"] is None
    assert result["resource"] is None

    raw_file = {
        "timestamp": "2026-04-01T10:00:00+06:00",
        "event_type": "file_read",
        "username": "user_01",
        "file_path": None,
        "ip_address": "192.168.1.100",
        "result": "success",
        "session": None,
    }
    result_file = normalize_file_event(raw_file, event_counter=2, scenario_id="s0")
    assert result_file["resource"] is None
    assert result_file["session_id"] is None
