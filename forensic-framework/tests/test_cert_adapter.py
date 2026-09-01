"""Tests for the CERT r4.2 adapter.

These tests do NOT require the full r4.2 tarball; they synthesise a tiny
fake tarball with the same on-disk shape (a few rows per CSV plus an
answers file). The goal is to lock the schema, the windowing logic, the
label balance, the volume-match resampling, and the no-leakage guarantee.

A separate integration step (run by `run_real_data.py --source cert`) is
what actually loads r4.2 — these unit tests run in 0.1 s without the data.
"""

from __future__ import annotations

import bz2
import csv
import io
import random
import tarfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from app.ingestion.adapters.cert_insider import (
    _build_attack_windows,
    _build_benign_windows,
    _downsample_window,
    _parse_cert_timestamp,
    load_insiders,
    load_scenarios,
    stream_events_for_users,
)


REQUIRED_EVENT_FIELDS = {
    "event_id", "timestamp", "source_type", "user", "action",
    "resource", "source_ip", "status", "session_id", "severity", "metadata",
}

ALLOWED_SOURCE_TYPES = {
    "auth", "file_access", "admin", "network", "database",
    "web_server", "email",
}


# ---------------------------------------------------------------------------
# Synthetic tarball
# ---------------------------------------------------------------------------

def _ts(date_str: str) -> str:
    return date_str


def _csv_bytes(header: list[str], rows: list[list[str]]) -> bytes:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(header)
    for row in rows:
        w.writerow(row)
    return buf.getvalue().encode("utf-8")


@pytest.fixture
def fake_cert_dir(tmp_path: Path) -> Path:
    """Build a fake CERT directory containing a tiny r4.2 tarball + answers."""
    cert_dir = tmp_path / "cert"
    cert_dir.mkdir()

    # ---------- answers.tar.bz2 ----------
    answers_buf = io.BytesIO()
    with tarfile.open(fileobj=answers_buf, mode="w:bz2") as tar:
        insiders_csv = _csv_bytes(
            ["dataset", "scenario", "details", "user", "start", "end"],
            [
                ["4.2", "1", "r4.2-1-IUSER1.csv", "IUSER1",
                 "10/05/2010 09:00:00", "10/25/2010 17:00:00"],
                ["4.2", "1", "r4.2-1-IUSER2.csv", "IUSER2",
                 "11/02/2010 08:00:00", "11/20/2010 18:00:00"],
            ],
        )
        info = tarfile.TarInfo("answers/insiders.csv")
        info.size = len(insiders_csv)
        tar.addfile(info, io.BytesIO(insiders_csv))
    (cert_dir / "answers.tar.bz2").write_bytes(answers_buf.getvalue())

    # ---------- r4.2.tar.bz2 ----------
    main_buf = io.BytesIO()
    with tarfile.open(fileobj=main_buf, mode="w:bz2") as tar:
        # logon.csv (insiders + benign users)
        logon_rows = []
        for u in ["IUSER1", "IUSER2", "BUSER1", "BUSER2", "BUSER3",
                  "BUSER4", "BUSER5"]:
            # 30 days × 2 logon events per day, October–November 2010
            for d in range(30):
                day = (datetime(2010, 10, 1) + timedelta(days=d))
                logon_rows.append([
                    f"id_{u}_{d}_in", day.strftime("%m/%d/%Y 09:00:00"),
                    u, "PC-1", "Logon",
                ])
                logon_rows.append([
                    f"id_{u}_{d}_out", day.strftime("%m/%d/%Y 17:00:00"),
                    u, "PC-1", "Logoff",
                ])
            for d in range(30):
                day = (datetime(2010, 11, 1) + timedelta(days=d))
                logon_rows.append([
                    f"id_{u}_n{d}_in", day.strftime("%m/%d/%Y 09:00:00"),
                    u, "PC-1", "Logon",
                ])
        logon_csv = _csv_bytes(
            ["id", "date", "user", "pc", "activity"], logon_rows,
        )
        info = tarfile.TarInfo("r4.2/logon.csv")
        info.size = len(logon_csv)
        tar.addfile(info, io.BytesIO(logon_csv))

        # device.csv (insider gets extra USB activity in attack window)
        device_rows = []
        # Benign users: occasional device events
        for u in ["BUSER1", "BUSER2"]:
            device_rows.append([
                f"d_{u}", "10/15/2010 10:00:00", u, "PC-1", "Connect",
            ])
            device_rows.append([
                f"d_{u}_off", "10/15/2010 10:30:00", u, "PC-1", "Disconnect",
            ])
        # Insider device storms
        for d in range(5, 25):
            device_rows.append([
                f"d_IUSER1_{d}",
                (datetime(2010, 10, 1) + timedelta(days=d)).strftime(
                    "%m/%d/%Y 10:00:00"),
                "IUSER1", "PC-1", "Connect",
            ])
        for d in range(2, 20):
            device_rows.append([
                f"d_IUSER2_{d}",
                (datetime(2010, 11, 1) + timedelta(days=d)).strftime(
                    "%m/%d/%Y 11:00:00"),
                "IUSER2", "PC-1", "Connect",
            ])
        device_csv = _csv_bytes(
            ["id", "date", "user", "pc", "activity"], device_rows,
        )
        info = tarfile.TarInfo("r4.2/device.csv")
        info.size = len(device_csv)
        tar.addfile(info, io.BytesIO(device_csv))

        # http.csv (a few hits each)
        http_rows = []
        for u in ["IUSER1", "BUSER1", "BUSER2", "BUSER3"]:
            for d in range(0, 30, 3):
                http_rows.append([
                    f"h_{u}_{d}",
                    (datetime(2010, 10, 1) + timedelta(days=d)).strftime(
                        "%m/%d/%Y 14:00:00"),
                    u, "PC-1",
                    "http://example.com/page",
                    "lorem ipsum",
                ])
        http_csv = _csv_bytes(
            ["id", "date", "user", "pc", "url", "content"], http_rows,
        )
        info = tarfile.TarInfo("r4.2/http.csv")
        info.size = len(http_csv)
        tar.addfile(info, io.BytesIO(http_csv))

        # file.csv (insider copies sensitive files)
        file_rows = []
        for d in range(8, 22):
            file_rows.append([
                f"f_IUSER1_{d}",
                (datetime(2010, 10, 1) + timedelta(days=d)).strftime(
                    "%m/%d/%Y 11:30:00"),
                "IUSER1", "PC-1",
                f"R:/exfil/secret_{d}.docx", "Copy",
            ])
        file_csv = _csv_bytes(
            ["id", "date", "user", "pc", "filename", "activity"], file_rows,
        )
        info = tarfile.TarInfo("r4.2/file.csv")
        info.size = len(file_csv)
        tar.addfile(info, io.BytesIO(file_csv))

        # email.csv (small)
        email_rows = []
        for u in ["IUSER1", "BUSER1", "BUSER2"]:
            for d in range(0, 30, 5):
                email_rows.append([
                    f"e_{u}_{d}",
                    (datetime(2010, 10, 1) + timedelta(days=d)).strftime(
                        "%m/%d/%Y 12:00:00"),
                    u, "PC-1",
                    "recip@dtaa.com", "", "",
                    f"{u}@dtaa.com", "10000", "1", "hello",
                ])
        email_csv = _csv_bytes(
            ["id", "date", "user", "pc", "to", "cc", "bcc", "from",
             "size", "attachments", "content"], email_rows,
        )
        info = tarfile.TarInfo("r4.2/email.csv")
        info.size = len(email_csv)
        tar.addfile(info, io.BytesIO(email_csv))
    (cert_dir / "r4.2.tar.bz2").write_bytes(main_buf.getvalue())

    return cert_dir


# ---------------------------------------------------------------------------
# Insider parsing
# ---------------------------------------------------------------------------

def test_load_insiders(fake_cert_dir: Path):
    from app.ingestion.adapters.cert_insider import ensure_answers_extracted
    ensure_answers_extracted(fake_cert_dir)
    insiders = load_insiders(fake_cert_dir, release="4.2")
    assert set(insiders) == {"IUSER1", "IUSER2"}
    assert insiders["IUSER1"]["scenario"] == "1"
    assert insiders["IUSER1"]["start"].month == 10


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------

def test_stream_events_for_users(fake_cert_dir: Path):
    evs = stream_events_for_users(
        fake_cert_dir / "r4.2.tar.bz2", target_users={"IUSER1"},
    )
    assert "IUSER1" in evs
    types = {e["source_type"] for e in evs["IUSER1"]}
    # All five families should appear for IUSER1 in the fixture.
    assert types == {"auth", "admin", "file_access", "email", "web_server"}
    for e in evs["IUSER1"]:
        assert REQUIRED_EVENT_FIELDS.issubset(e.keys())
        assert e["source_type"] in ALLOWED_SOURCE_TYPES
        # Timestamp parses
        datetime.fromisoformat(e["timestamp"])


# ---------------------------------------------------------------------------
# End-to-end load_scenarios on fixture
# ---------------------------------------------------------------------------

def test_load_scenarios_end_to_end(fake_cert_dir: Path):
    scenarios, manifest = load_scenarios(
        cert_dir=fake_cert_dir,
        n_attack=2, n_benign=2,
        max_events_per_window=220, seed=42,
    )
    labels = [s["label"] for s in scenarios]
    assert labels.count("ATTACK") >= 1
    assert labels.count("BENIGN") >= 1
    for s in scenarios:
        assert s["label"] in {"BENIGN", "ATTACK"}
        assert s["events"], f"{s['scenario_id']}: empty events"
        for e in s["events"]:
            assert REQUIRED_EVENT_FIELDS.issubset(e.keys())
    # Manifest is consistent
    assert manifest["release"] == "4.2"
    assert len(manifest["windows"]) == len(scenarios)


# ---------------------------------------------------------------------------
# Downsampling preserves admin/file events
# ---------------------------------------------------------------------------

def test_downsample_preserves_critical_event_types():
    rng = random.Random(0)
    # 100 logon events + 5 file events; cap at 20
    events = []
    for i in range(100):
        events.append({
            "event_id": f"l{i}", "timestamp": f"2010-10-{(i % 28) + 1:02d}T10:00:00+00:00",
            "source_type": "auth", "user": "U", "action": "login",
            "resource": None, "source_ip": "pc:PC", "status": "success",
            "session_id": "s", "severity": "info", "metadata": {},
        })
    for i in range(5):
        events.append({
            "event_id": f"f{i}", "timestamp": f"2010-10-{(i % 28) + 1:02d}T11:00:00+00:00",
            "source_type": "file_access", "user": "U", "action": "file_copy",
            "resource": "f.txt", "source_ip": "pc:PC", "status": "success",
            "session_id": "s", "severity": "warning", "metadata": {},
        })
    out, ds, orig = _downsample_window(events, max_events=20, rng=rng)
    assert ds is True
    assert orig == 105
    assert len(out) <= 20
    # All 5 file events survived
    assert sum(1 for e in out if e["source_type"] == "file_access") == 5


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_determinism(fake_cert_dir: Path):
    s1, m1 = load_scenarios(cert_dir=fake_cert_dir, n_attack=2, n_benign=2, seed=42)
    s2, m2 = load_scenarios(cert_dir=fake_cert_dir, n_attack=2, n_benign=2, seed=42)
    assert [s["scenario_id"] for s in s1] == [s["scenario_id"] for s in s2]
    # Event lists byte-equal too
    for a, b in zip(s1, s2):
        assert a["events"] == b["events"]


# ---------------------------------------------------------------------------
# No leakage: ground-truth fields must not appear in events
# ---------------------------------------------------------------------------

_LEAKAGE_KEYS = {"insider", "scenario_type", "ground_truth", "label",
                  "is_insider", "attack_window"}


def test_no_answers_leakage_into_events(fake_cert_dir: Path):
    scenarios, _ = load_scenarios(cert_dir=fake_cert_dir, n_attack=2, n_benign=2)
    for s in scenarios:
        for e in s["events"]:
            md_keys = set(e.get("metadata", {}).keys())
            assert not (_LEAKAGE_KEYS & md_keys), (
                f"{s['scenario_id']} event {e['event_id']}: leakage "
                f"{_LEAKAGE_KEYS & md_keys}"
            )
            # Event values must not include ground-truth tokens
            md_blob = repr(e.get("metadata", {})).lower()
            assert "is_insider" not in md_blob
            assert "ground_truth" not in md_blob


def test_volume_match_metadata_attached(fake_cert_dir: Path):
    """BENIGN windows record the median-percent-diff against attack counts."""
    scenarios, _ = load_scenarios(cert_dir=fake_cert_dir, n_attack=2, n_benign=2)
    benign = [s for s in scenarios if s["label"] == "BENIGN"]
    if benign:
        assert "volume_match_pct_diff" in benign[0]
