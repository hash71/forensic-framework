"""
Cross-source event correlation and temporal pattern matching.

Performs lightweight linking of normalized forensic events to surface
suspicious patterns: credential stuffing, privilege escalation chains,
after-hours activity, unusual volume bursts, and cross-source continuity.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
NORMALIZED_DIR = DATA_DIR / "normalized"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_ts(ts_str: str) -> datetime:
    """Parse an ISO-8601 timestamp string into a datetime object."""
    return datetime.fromisoformat(ts_str)


def _parse_hour_range(hour_range: str) -> tuple[int, int]:
    """Parse a string like '08:30-18:00' into (start_minute_of_day, end_minute_of_day)."""
    start_str, end_str = hour_range.split("-")
    sh, sm = map(int, start_str.split(":"))
    eh, em = map(int, end_str.split(":"))
    return sh * 60 + sm, eh * 60 + em


def _minute_of_day(dt: datetime) -> int:
    return dt.hour * 60 + dt.minute


# ---------------------------------------------------------------------------
# 1. Load baselines
# ---------------------------------------------------------------------------

def load_baselines() -> dict:
    """Load user baselines from data/user_baselines.json."""
    baselines_path = DATA_DIR / "user_baselines.json"
    with open(baselines_path, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# 2. Login activity correlation
# ---------------------------------------------------------------------------

def correlate_login_activity(events: list[dict]) -> list[dict]:
    """Find login-related patterns such as credential stuffing and unusual IPs.

    Detects:
    - Failed login attempts followed by a successful login (credential stuffing).
    - Logins from IPs not present in the user baseline.

    Returns a list of correlation findings.
    """
    baselines = load_baselines()
    findings: list[dict] = []

    # Group auth events by user, preserving order
    user_auth_events: dict[str, list[dict]] = defaultdict(list)
    for evt in events:
        if evt.get("source_type") == "auth" and evt.get("action") in (
            "login", "login_failed",
        ):
            user_auth_events[evt["user"]].append(evt)

    for user, auth_evts in user_auth_events.items():
        # Sort by timestamp
        auth_evts.sort(key=lambda e: e["timestamp"])

        # --- Credential stuffing pattern: consecutive failures then success ---
        fail_streak: list[dict] = []
        for evt in auth_evts:
            if evt["action"] == "login_failed":
                fail_streak.append(evt)
            elif evt["action"] == "login" and evt["status"] == "success":
                if fail_streak:
                    all_ids = [e["event_id"] for e in fail_streak] + [evt["event_id"]]
                    findings.append({
                        "type": "credential_stuffing",
                        "event_ids": all_ids,
                        "description": (
                            f"{len(fail_streak)} failed login(s) for {user} "
                            f"followed by successful login from {evt['source_ip']}"
                        ),
                        "severity": "critical",
                    })
                fail_streak = []
            else:
                fail_streak = []

        # --- Unusual IP detection ---
        user_baseline = baselines.get(user, {})
        normal_ips = set(user_baseline.get("normal_ips", []))
        for evt in auth_evts:
            if evt["action"] == "login" and evt["status"] == "success":
                if normal_ips and evt["source_ip"] not in normal_ips:
                    findings.append({
                        "type": "unusual_login_ip",
                        "event_ids": [evt["event_id"]],
                        "description": (
                            f"{user} logged in from unusual IP {evt['source_ip']} "
                            f"(expected: {', '.join(sorted(normal_ips))})"
                        ),
                        "severity": "warning",
                    })

    return findings


# ---------------------------------------------------------------------------
# 3. Privilege and access correlation
# ---------------------------------------------------------------------------

def correlate_privilege_and_access(events: list[dict]) -> list[dict]:
    """Find privilege escalation followed by file downloads or new resource access.

    Detects:
    - Privilege change events followed by file downloads within the same session
      or by the same user shortly after.
    - Access to resources outside the user's normal directories after a privilege change.

    Returns a list of correlation findings.
    """
    baselines = load_baselines()
    findings: list[dict] = []

    sorted_events = sorted(events, key=lambda e: e["timestamp"])

    # Collect privilege change events per user
    priv_changes: dict[str, list[dict]] = defaultdict(list)
    for evt in sorted_events:
        if evt.get("action") == "privilege_change":
            priv_changes[evt["user"]].append(evt)

    if not priv_changes:
        return findings

    for user, changes in priv_changes.items():
        user_baseline = baselines.get(user, {})
        normal_dirs = set(user_baseline.get("normal_directories", []))

        for change_evt in changes:
            change_ts = _parse_ts(change_evt["timestamp"])

            # Collect subsequent events by same user within 24 hours
            subsequent_downloads: list[dict] = []
            subsequent_new_access: list[dict] = []

            for evt in sorted_events:
                if evt["user"] != user:
                    continue
                evt_ts = _parse_ts(evt["timestamp"])
                if evt_ts <= change_ts:
                    continue
                if evt_ts > change_ts + timedelta(hours=24):
                    break

                if evt.get("action") == "file_download":
                    subsequent_downloads.append(evt)

                # Check for access outside normal directories
                resource = evt.get("resource") or ""
                if resource and evt.get("source_type") == "file_access":
                    in_normal = any(resource.startswith(d) for d in normal_dirs)
                    if not in_normal:
                        subsequent_new_access.append(evt)

            if subsequent_downloads:
                download_ids = [e["event_id"] for e in subsequent_downloads]
                findings.append({
                    "type": "privilege_escalation_then_download",
                    "event_ids": [change_evt["event_id"]] + download_ids,
                    "description": (
                        f"{user} had privilege change then downloaded "
                        f"{len(subsequent_downloads)} file(s) within 24h"
                    ),
                    "severity": "critical",
                })

            if subsequent_new_access:
                access_ids = [e["event_id"] for e in subsequent_new_access]
                findings.append({
                    "type": "new_resource_access_after_privilege_change",
                    "event_ids": [change_evt["event_id"]] + access_ids,
                    "description": (
                        f"{user} accessed {len(subsequent_new_access)} resource(s) "
                        f"outside normal directories after privilege change"
                    ),
                    "severity": "warning",
                })

    return findings


# ---------------------------------------------------------------------------
# 4. Temporal pattern correlation
# ---------------------------------------------------------------------------

def correlate_temporal_patterns(events: list[dict], baselines: dict) -> list[dict]:
    """Find time-based anomalies such as after-hours activity and volume spikes.

    Detects:
    - Activity outside the user's normal working hours.
    - Unusual volume of events in short time windows (e.g., 30 minutes).

    Returns a list of correlation findings.
    """
    findings: list[dict] = []
    sorted_events = sorted(events, key=lambda e: e["timestamp"])

    # --- After-hours activity ---
    user_afterhours: dict[str, list[dict]] = defaultdict(list)
    for evt in sorted_events:
        user = evt.get("user")
        if not user:
            continue
        baseline = baselines.get(user, {})
        normal_hours = baseline.get("normal_hours")
        if not normal_hours:
            continue

        start_min, end_min = _parse_hour_range(normal_hours)
        evt_min = _minute_of_day(_parse_ts(evt["timestamp"]))
        if evt_min < start_min or evt_min > end_min:
            user_afterhours[user].append(evt)

    for user, ah_events in user_afterhours.items():
        if ah_events:
            findings.append({
                "type": "after_hours_activity",
                "event_ids": [e["event_id"] for e in ah_events],
                "description": (
                    f"{user} had {len(ah_events)} event(s) outside normal "
                    f"working hours ({baselines[user]['normal_hours']})"
                ),
                "severity": "warning",
            })

    # --- Unusual volume in short windows (30-minute sliding window) ---
    WINDOW_MINUTES = 30
    VOLUME_THRESHOLD = 5  # more than 5 events in 30 min is unusual

    user_events: dict[str, list[dict]] = defaultdict(list)
    for evt in sorted_events:
        user = evt.get("user")
        if user:
            user_events[user].append(evt)

    for user, u_events in user_events.items():
        u_events.sort(key=lambda e: e["timestamp"])
        i = 0
        reported_windows: set[str] = set()
        for j in range(len(u_events)):
            ts_j = _parse_ts(u_events[j]["timestamp"])
            # Advance i to keep window within WINDOW_MINUTES
            while i < j:
                ts_i = _parse_ts(u_events[i]["timestamp"])
                if (ts_j - ts_i) > timedelta(minutes=WINDOW_MINUTES):
                    i += 1
                else:
                    break

            window_size = j - i + 1
            if window_size > VOLUME_THRESHOLD:
                # Deduplicate: report once per distinct starting event
                window_key = u_events[i]["event_id"]
                if window_key not in reported_windows:
                    reported_windows.add(window_key)
                    window_events = u_events[i:j + 1]
                    ts_start = _parse_ts(window_events[0]["timestamp"])
                    ts_end = _parse_ts(window_events[-1]["timestamp"])
                    findings.append({
                        "type": "unusual_volume",
                        "event_ids": [e["event_id"] for e in window_events],
                        "description": (
                            f"{user} generated {window_size} events in "
                            f"{int((ts_end - ts_start).total_seconds() / 60)} minutes "
                            f"(threshold: {VOLUME_THRESHOLD})"
                        ),
                        "severity": "warning",
                    })

    return findings


# ---------------------------------------------------------------------------
# 5. Cross-source correlation
# ---------------------------------------------------------------------------

def correlate_cross_source(events: list[dict], baselines: dict) -> list[dict]:
    """Cross-source linking: auth + file_access + admin events for the same user.

    Detects:
    - Users appearing across multiple source types (auth, file_access, admin).
    - Session continuity issues (file access without a preceding login).

    Returns a list of correlation findings.
    """
    findings: list[dict] = []
    sorted_events = sorted(events, key=lambda e: e["timestamp"])

    # --- Multi-source user activity ---
    user_sources: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for evt in sorted_events:
        user = evt.get("user")
        source_type = evt.get("source_type")
        if user and source_type:
            user_sources[user][source_type].append(evt)

    for user, sources in user_sources.items():
        source_types = sorted(sources.keys())
        if len(source_types) >= 2:
            all_ids = []
            for st in source_types:
                all_ids.extend(e["event_id"] for e in sources[st])
            findings.append({
                "type": "cross_source_activity",
                "event_ids": all_ids,
                "description": (
                    f"{user} has activity across {len(source_types)} source types: "
                    f"{', '.join(source_types)}"
                ),
                "severity": "info",
            })

    # --- Session continuity: file/admin events without a preceding login ---
    user_sessions: dict[str, set[str]] = defaultdict(set)
    # Track which sessions have a login event
    for evt in sorted_events:
        if evt.get("source_type") == "auth" and evt.get("action") == "login" and evt.get("status") == "success":
            session_id = evt.get("session_id")
            if session_id:
                user_sessions[evt["user"]].add(session_id)

    orphan_events: dict[str, list[dict]] = defaultdict(list)
    for evt in sorted_events:
        if evt.get("source_type") in ("file_access", "admin"):
            user = evt.get("user")
            session_id = evt.get("session_id")
            if session_id and session_id not in user_sessions.get(user, set()):
                orphan_events[user].append(evt)

    for user, orphans in orphan_events.items():
        findings.append({
            "type": "session_continuity_gap",
            "event_ids": [e["event_id"] for e in orphans],
            "description": (
                f"{user} has {len(orphans)} event(s) in sessions with "
                f"no corresponding login event"
            ),
            "severity": "warning",
        })

    return findings


# ---------------------------------------------------------------------------
# 6. Correlate a single scenario
# ---------------------------------------------------------------------------

def correlate_scenario(scenario_num: int) -> dict:
    """Load normalized events for a scenario, run all correlators, return results."""
    events_path = NORMALIZED_DIR / f"scenario_{scenario_num}_events.json"
    with open(events_path, "r") as f:
        events = json.load(f)

    baselines = load_baselines()

    all_findings: list[dict] = []
    all_findings.extend(correlate_login_activity(events))
    all_findings.extend(correlate_privilege_and_access(events))
    all_findings.extend(correlate_temporal_patterns(events, baselines))
    all_findings.extend(correlate_cross_source(events, baselines))

    severity_summary: dict[str, int] = defaultdict(int)
    for f in all_findings:
        severity_summary[f["severity"]] += 1

    return {
        "scenario": scenario_num,
        "findings": all_findings,
        "finding_count": len(all_findings),
        "severity_summary": dict(severity_summary),
    }


# ---------------------------------------------------------------------------
# 7. Correlate all scenarios
# ---------------------------------------------------------------------------

def correlate_all() -> dict:
    """Run correlation for every scenario found in data/normalized/.

    Saves individual results to data/normalized/scenario_{N}_correlations.json
    and returns a combined summary.
    """
    scenario_files = sorted(NORMALIZED_DIR.glob("scenario_*_events.json"))
    results: dict[int, dict] = {}

    for sf in scenario_files:
        # Extract scenario number from filename
        name = sf.stem  # e.g. "scenario_3_events"
        num_str = name.replace("scenario_", "").replace("_events", "")
        try:
            scenario_num = int(num_str)
        except ValueError:
            continue

        result = correlate_scenario(scenario_num)
        results[scenario_num] = result

        out_path = NORMALIZED_DIR / f"scenario_{scenario_num}_correlations.json"
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)

    return {
        "scenarios_processed": len(results),
        "results": results,
    }


# ---------------------------------------------------------------------------
# 8. CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    summary = correlate_all()

    print(f"Processed {summary['scenarios_processed']} scenario(s)\n")
    for num in sorted(summary["results"]):
        r = summary["results"][num]
        print(f"--- Scenario {num} ---")
        print(f"  Findings: {r['finding_count']}")
        for sev, count in sorted(r["severity_summary"].items()):
            print(f"    {sev}: {count}")
        for finding in r["findings"]:
            print(f"  [{finding['severity'].upper()}] {finding['type']}: {finding['description']}")
        print()
