"""
Rule Engine for forensic investigation framework.

Implements 12 detection rules (R001-R012) that analyze normalized events
against user baselines to generate security alerts.
"""

import json
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger("forensic.rules")

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def load_baselines() -> dict:
    """Load user baselines from data/user_baselines.json."""
    baselines_path = PROJECT_ROOT / "data" / "user_baselines.json"
    with open(baselines_path, "r") as f:
        return json.load(f)


def load_rules() -> list[dict]:
    """Load detection rules from config/rules.yaml."""
    rules_path = PROJECT_ROOT / "config" / "rules.yaml"
    with open(rules_path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


def _parse_timestamp(ts_str: str) -> datetime:
    """Parse an ISO format timestamp string."""
    return datetime.fromisoformat(ts_str)


def _parse_hours_range(hours_str: str) -> tuple[tuple[int, int], tuple[int, int]]:
    """Parse 'HH:MM-HH:MM' into ((start_h, start_m), (end_h, end_m))."""
    start_str, end_str = hours_str.split("-")
    sh, sm = map(int, start_str.split(":"))
    eh, em = map(int, end_str.split(":"))
    return (sh, sm), (eh, em)


def _is_within_hours(ts: datetime, hours_str: str) -> bool:
    """Check if timestamp falls within the normal hours range."""
    (sh, sm), (eh, em) = _parse_hours_range(hours_str)
    start_minutes = sh * 60 + sm
    end_minutes = eh * 60 + em
    event_minutes = ts.hour * 60 + ts.minute
    return start_minutes <= event_minutes <= end_minutes


def _make_alert(
    rule_id: str,
    rule_name: str,
    severity: str,
    event_ids: list[str],
    user: str,
    description: str,
    timestamp: str,
) -> dict:
    """Create a standardized alert dictionary."""
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "event_ids": event_ids,
        "user": user,
        "description": description,
        "timestamp": timestamp,
    }


# ---------------------------------------------------------------------------
# R001: unusual_login_ip
# ---------------------------------------------------------------------------
def check_unusual_ip(events: list[dict], baselines: dict) -> list[dict]:
    """R001: Flag logins from IPs not in user's normal_ips."""
    alerts = []
    for evt in events:
        if evt.get("action") != "login":
            continue
        user = evt.get("user", "")
        baseline = baselines.get(user)
        if not baseline:
            continue
        normal_ips = baseline.get("normal_ips", [])
        source_ip = evt.get("source_ip", "")
        if source_ip and source_ip not in normal_ips:
            alerts.append(
                _make_alert(
                    rule_id="R001",
                    rule_name="unusual_login_ip",
                    severity="warning",
                    event_ids=[evt["event_id"]],
                    user=user,
                    description=(
                        f"Login from unusual IP {source_ip}. "
                        f"Normal IPs: {normal_ips}"
                    ),
                    timestamp=evt["timestamp"],
                )
            )
    return alerts


# ---------------------------------------------------------------------------
# R002: off_hours_access
# ---------------------------------------------------------------------------
def check_off_hours(events: list[dict], baselines: dict) -> list[dict]:
    """R002: Flag any event that occurs outside user's normal_hours."""
    alerts = []
    for evt in events:
        user = evt.get("user", "")
        baseline = baselines.get(user)
        if not baseline:
            continue
        normal_hours = baseline.get("normal_hours")
        if not normal_hours:
            continue
        ts = _parse_timestamp(evt["timestamp"])
        if not _is_within_hours(ts, normal_hours):
            alerts.append(
                _make_alert(
                    rule_id="R002",
                    rule_name="off_hours_access",
                    severity="warning",
                    event_ids=[evt["event_id"]],
                    user=user,
                    description=(
                        f"Activity at {ts.strftime('%H:%M')} outside normal hours "
                        f"({normal_hours})"
                    ),
                    timestamp=evt["timestamp"],
                )
            )
    return alerts


# ---------------------------------------------------------------------------
# R003: privilege_escalation
# ---------------------------------------------------------------------------
def check_privilege_escalation(events: list[dict], baselines: dict) -> list[dict]:
    """R003: Flag any privilege_change action."""
    alerts = []
    for evt in events:
        if evt.get("action") != "privilege_change":
            continue
        user = evt.get("user", "")
        alerts.append(
            _make_alert(
                rule_id="R003",
                rule_name="privilege_escalation",
                severity="critical",
                event_ids=[evt["event_id"]],
                user=user,
                description=(
                    f"Privilege change detected for {user}. "
                    f"Resource: {evt.get('resource', 'N/A')}"
                ),
                timestamp=evt["timestamp"],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R004: bulk_download
# ---------------------------------------------------------------------------
def check_bulk_download(events: list[dict], baselines: dict) -> list[dict]:
    """R004: Flag when >5 file_downloads occur within a 30-min sliding window per user."""
    alerts = []

    # Group download events by user
    downloads_by_user: dict[str, list[dict]] = {}
    for evt in events:
        if evt.get("action") != "file_download":
            continue
        user = evt.get("user", "")
        downloads_by_user.setdefault(user, []).append(evt)

    window = timedelta(minutes=30)

    for user, dl_events in downloads_by_user.items():
        # Sort by timestamp
        dl_events.sort(key=lambda e: e["timestamp"])
        timestamps = [_parse_timestamp(e["timestamp"]) for e in dl_events]

        # Sliding window: for each event, count how many events fall within
        # [event_time, event_time + 30min]
        alerted_ids: set[str] = set()
        for i, ts_i in enumerate(timestamps):
            window_end = ts_i + window
            window_events = []
            for j in range(i, len(timestamps)):
                if timestamps[j] <= window_end:
                    window_events.append(dl_events[j])
                else:
                    break
            if len(window_events) > 5:
                new_ids = [
                    e["event_id"]
                    for e in window_events
                    if e["event_id"] not in alerted_ids
                ]
                if new_ids:
                    all_ids = [e["event_id"] for e in window_events]
                    for eid in all_ids:
                        alerted_ids.add(eid)
                    alerts.append(
                        _make_alert(
                            rule_id="R004",
                            rule_name="bulk_download",
                            severity="critical",
                            event_ids=all_ids,
                            user=user,
                            description=(
                                f"Bulk download detected: {len(window_events)} files "
                                f"downloaded within 30 minutes "
                                f"(window start: {ts_i.isoformat()})"
                            ),
                            timestamp=dl_events[i]["timestamp"],
                        )
                    )

    return alerts


# ---------------------------------------------------------------------------
# R005: cross_department_access
# ---------------------------------------------------------------------------
def check_cross_department(events: list[dict], baselines: dict) -> list[dict]:
    """R005: Flag access to resources outside user's normal_directories."""
    alerts = []
    for evt in events:
        resource = evt.get("resource")
        if not resource or resource in ("null", "role"):
            continue
        # Skip non-file events (auth events, etc.)
        if evt.get("source_type") not in ("file_access",):
            continue
        user = evt.get("user", "")
        baseline = baselines.get(user)
        if not baseline:
            continue
        normal_dirs = baseline.get("normal_directories", [])
        if not normal_dirs:
            continue
        # Check if resource starts with any of the normal directories
        in_normal = any(resource.startswith(d) for d in normal_dirs)
        if not in_normal:
            alerts.append(
                _make_alert(
                    rule_id="R005",
                    rule_name="cross_department_access",
                    severity="warning",
                    event_ids=[evt["event_id"]],
                    user=user,
                    description=(
                        f"Cross-department access: {resource} is outside "
                        f"normal directories {normal_dirs}"
                    ),
                    timestamp=evt["timestamp"],
                )
            )
    return alerts


# ---------------------------------------------------------------------------
# R006: log_deletion
# ---------------------------------------------------------------------------
def check_log_deletion(events: list[dict], baselines: dict) -> list[dict]:
    """R006: Flag any log_delete action."""
    alerts = []
    for evt in events:
        if evt.get("action") != "log_delete":
            continue
        user = evt.get("user", "")
        alerts.append(
            _make_alert(
                rule_id="R006",
                rule_name="log_deletion",
                severity="critical",
                event_ids=[evt["event_id"]],
                user=user,
                description=(
                    f"Log deletion detected by {user}. "
                    f"Target: {evt.get('resource', 'N/A')}"
                ),
                timestamp=evt["timestamp"],
            )
        )
    return alerts


# ---------------------------------------------------------------------------
# R007: failed_login_spike
# ---------------------------------------------------------------------------
def check_failed_login_spike(events: list[dict], baselines: dict) -> list[dict]:
    """R007: Flag when >=2 login failures occur within a 5-min sliding window per user."""
    alerts = []

    # Group failed logins by user
    failures_by_user: dict[str, list[dict]] = {}
    for evt in events:
        if evt.get("action") != "login_failed":
            continue
        user = evt.get("user", "")
        failures_by_user.setdefault(user, []).append(evt)

    window = timedelta(minutes=5)

    for user, fail_events in failures_by_user.items():
        fail_events.sort(key=lambda e: e["timestamp"])
        timestamps = [_parse_timestamp(e["timestamp"]) for e in fail_events]

        alerted_ids: set[str] = set()
        for i, ts_i in enumerate(timestamps):
            window_end = ts_i + window
            window_events = []
            for j in range(i, len(timestamps)):
                if timestamps[j] <= window_end:
                    window_events.append(fail_events[j])
                else:
                    break
            if len(window_events) >= 2:
                new_ids = [
                    e["event_id"]
                    for e in window_events
                    if e["event_id"] not in alerted_ids
                ]
                if new_ids:
                    all_ids = [e["event_id"] for e in window_events]
                    for eid in all_ids:
                        alerted_ids.add(eid)
                    alerts.append(
                        _make_alert(
                            rule_id="R007",
                            rule_name="failed_login_spike",
                            severity="warning",
                            event_ids=all_ids,
                            user=user,
                            description=(
                                f"Failed login spike: {len(window_events)} failures "
                                f"within 5 minutes for {user} "
                                f"(window start: {ts_i.isoformat()})"
                            ),
                            timestamp=fail_events[i]["timestamp"],
                        )
                    )

    return alerts


# ---------------------------------------------------------------------------
# R008: privilege_then_download
# ---------------------------------------------------------------------------
def check_privilege_then_download(
    events: list[dict], baselines: dict
) -> list[dict]:
    """R008: Flag privilege_change followed by file_download within 30min for same user."""
    alerts = []
    window = timedelta(minutes=30)

    # Sort events by timestamp
    sorted_events = sorted(events, key=lambda e: e["timestamp"])

    # Find all privilege_change events
    priv_events = [e for e in sorted_events if e.get("action") == "privilege_change"]
    download_events = [
        e for e in sorted_events if e.get("action") == "file_download"
    ]

    for priv_evt in priv_events:
        priv_user = priv_evt.get("user", "")
        priv_ts = _parse_timestamp(priv_evt["timestamp"])
        window_end = priv_ts + window

        following_downloads = [
            dl
            for dl in download_events
            if dl.get("user") == priv_user
            and priv_ts < _parse_timestamp(dl["timestamp"]) <= window_end
        ]

        if following_downloads:
            all_ids = [priv_evt["event_id"]] + [
                dl["event_id"] for dl in following_downloads
            ]
            alerts.append(
                _make_alert(
                    rule_id="R008",
                    rule_name="privilege_then_download",
                    severity="critical",
                    event_ids=all_ids,
                    user=priv_user,
                    description=(
                        f"Privilege escalation at {priv_evt['timestamp']} followed by "
                        f"{len(following_downloads)} file download(s) within 30 minutes"
                    ),
                    timestamp=priv_evt["timestamp"],
                )
            )

    return alerts


# ---------------------------------------------------------------------------
# R009: dns_tunnel_detection
# ---------------------------------------------------------------------------
def check_dns_tunnel(events: list[dict], baselines: dict) -> list[dict]:
    """R009: Flag when >20 dns_query events to the same domain occur within 5 minutes."""
    alerts = []

    dns_events = [
        e for e in events
        if e.get("source_type") == "network"
        and e.get("action") == "dns_query"
    ]

    if not dns_events:
        return alerts

    # Group by target domain (resource field)
    by_domain: dict[str, list[dict]] = {}
    for evt in dns_events:
        domain = evt.get("resource", "") or ""
        by_domain.setdefault(domain, []).append(evt)

    window = timedelta(minutes=5)

    for domain, domain_events in by_domain.items():
        domain_events.sort(key=lambda e: e["timestamp"])
        timestamps = [_parse_timestamp(e["timestamp"]) for e in domain_events]

        alerted_ids: set[str] = set()
        for i, ts_i in enumerate(timestamps):
            window_end = ts_i + window
            window_events = []
            for j in range(i, len(timestamps)):
                if timestamps[j] <= window_end:
                    window_events.append(domain_events[j])
                else:
                    break
            if len(window_events) > 20:
                new_ids = [
                    e["event_id"]
                    for e in window_events
                    if e["event_id"] not in alerted_ids
                ]
                if new_ids:
                    all_ids = [e["event_id"] for e in window_events]
                    for eid in all_ids:
                        alerted_ids.add(eid)
                    alerts.append(
                        _make_alert(
                            rule_id="R009",
                            rule_name="dns_tunnel_detection",
                            severity="critical",
                            event_ids=all_ids,
                            user="N/A",
                            description=(
                                f"Possible DNS tunnel: {len(window_events)} DNS queries "
                                f"to {domain} within 5 minutes "
                                f"(window start: {ts_i.isoformat()})"
                            ),
                            timestamp=domain_events[i]["timestamp"],
                        )
                    )

    return alerts


# ---------------------------------------------------------------------------
# R010: sql_injection_attempt
# ---------------------------------------------------------------------------
_SQL_KEYWORDS = re.compile(r"(UNION|SELECT|DROP|--|OR\s+1\s*=\s*1)", re.IGNORECASE)


def check_sql_injection(events: list[dict], baselines: dict) -> list[dict]:
    """R010: Flag web_server events with status 500 and SQL keywords in the URL."""
    alerts = []

    for evt in events:
        if evt.get("source_type") != "web_server":
            continue

        status = evt.get("status", "")
        try:
            status_code = int(status)
        except (ValueError, TypeError):
            continue

        if status_code != 500:
            continue

        url = evt.get("resource", "") or ""
        if _SQL_KEYWORDS.search(url):
            alerts.append(
                _make_alert(
                    rule_id="R010",
                    rule_name="sql_injection_attempt",
                    severity="critical",
                    event_ids=[evt["event_id"]],
                    user=evt.get("user", "N/A") or "N/A",
                    description=(
                        f"Possible SQL injection: URL {url} returned 500 and "
                        f"contains SQL keywords"
                    ),
                    timestamp=evt["timestamp"],
                )
            )

    return alerts


# ---------------------------------------------------------------------------
# R011: data_exfiltration_volume
# ---------------------------------------------------------------------------
def check_data_exfiltration_volume(events: list[dict], baselines: dict) -> list[dict]:
    """R011: Flag when total outbound bytes_transferred > 100 MB in a 30-min window."""
    alerts = []
    threshold = 100 * 1024 * 1024  # 100 MB

    network_events = [
        e for e in events
        if e.get("source_type") == "network"
        and e.get("metadata", {}).get("bytes_transferred", 0) > 0
    ]

    if not network_events:
        return alerts

    network_events.sort(key=lambda e: e["timestamp"])
    timestamps = [_parse_timestamp(e["timestamp"]) for e in network_events]
    window = timedelta(minutes=30)

    alerted_ids: set[str] = set()
    for i, ts_i in enumerate(timestamps):
        window_end = ts_i + window
        window_events = []
        total_bytes = 0
        for j in range(i, len(timestamps)):
            if timestamps[j] <= window_end:
                window_events.append(network_events[j])
                total_bytes += network_events[j].get("metadata", {}).get("bytes_transferred", 0)
            else:
                break
        if total_bytes > threshold:
            new_ids = [
                e["event_id"]
                for e in window_events
                if e["event_id"] not in alerted_ids
            ]
            if new_ids:
                all_ids = [e["event_id"] for e in window_events]
                for eid in all_ids:
                    alerted_ids.add(eid)
                mb = total_bytes / (1024 * 1024)
                alerts.append(
                    _make_alert(
                        rule_id="R011",
                        rule_name="data_exfiltration_volume",
                        severity="critical",
                        event_ids=all_ids,
                        user="N/A",
                        description=(
                            f"High data exfiltration volume: {mb:.1f} MB transferred "
                            f"in 30 minutes (window start: {ts_i.isoformat()})"
                        ),
                        timestamp=network_events[i]["timestamp"],
                    )
                )

    return alerts


# ---------------------------------------------------------------------------
# R012: lateral_movement
# ---------------------------------------------------------------------------
def check_lateral_movement(events: list[dict], baselines: dict) -> list[dict]:
    """R012: Flag same user authenticated from different server types within 30 min."""
    alerts = []
    window = timedelta(minutes=30)

    # Collect auth-like events across auth, database, and web_server
    auth_type_events: list[dict] = []
    for evt in events:
        source = evt.get("source_type", "")
        action = evt.get("action", "")
        user = evt.get("user")
        if not user:
            continue
        # Consider login-like actions from different source types
        if source == "auth" and action in ("login",):
            auth_type_events.append(evt)
        elif source == "database" and action in ("db_login",):
            auth_type_events.append(evt)
        elif source == "web_server" and action in ("http_request",):
            auth_type_events.append(evt)

    if not auth_type_events:
        return alerts

    # Group by user
    by_user: dict[str, list[dict]] = {}
    for evt in auth_type_events:
        by_user.setdefault(evt["user"], []).append(evt)

    for user, user_events in by_user.items():
        user_events.sort(key=lambda e: e["timestamp"])
        timestamps = [_parse_timestamp(e["timestamp"]) for e in user_events]

        alerted_windows: set[str] = set()
        for i, ts_i in enumerate(timestamps):
            window_end = ts_i + window
            window_evts = []
            window_sources = set()
            for j in range(i, len(timestamps)):
                if timestamps[j] <= window_end:
                    window_evts.append(user_events[j])
                    window_sources.add(user_events[j]["source_type"])
                else:
                    break
            # Need at least 2 different source types
            if len(window_sources) >= 2:
                window_key = f"{user}_{ts_i.isoformat()}"
                if window_key not in alerted_windows:
                    alerted_windows.add(window_key)
                    all_ids = [e["event_id"] for e in window_evts]
                    alerts.append(
                        _make_alert(
                            rule_id="R012",
                            rule_name="lateral_movement",
                            severity="warning",
                            event_ids=all_ids,
                            user=user,
                            description=(
                                f"Lateral movement detected: {user} authenticated across "
                                f"{sorted(window_sources)} within 30 minutes "
                                f"(window start: {ts_i.isoformat()})"
                            ),
                            timestamp=user_events[i]["timestamp"],
                        )
                    )

    return alerts


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def run_rules(events: list[dict], baselines: dict) -> list[dict]:
    """Run all 12 detection rules and return merged alert list sorted by timestamp."""
    all_alerts: list[dict] = []

    rule_checks = [
        check_unusual_ip,
        check_off_hours,
        check_privilege_escalation,
        check_bulk_download,
        check_cross_department,
        check_log_deletion,
        check_failed_login_spike,
        check_privilege_then_download,
        check_dns_tunnel,
        check_sql_injection,
        check_data_exfiltration_volume,
        check_lateral_movement,
    ]

    for check_fn in rule_checks:
        all_alerts.extend(check_fn(events, baselines))

    all_alerts.sort(key=lambda a: a["timestamp"])
    return all_alerts


def evaluate_scenario(scenario_num: int) -> dict:
    """Load normalized events and baselines, run rules, return results."""
    events_path = (
        PROJECT_ROOT / "data" / "normalized" / f"scenario_{scenario_num}_events.json"
    )
    with open(events_path, "r") as f:
        events = json.load(f)

    baselines = load_baselines()
    alerts = run_rules(events, baselines)

    rules_triggered = sorted(set(a["rule_id"] for a in alerts))
    severity_summary = {"warning": 0, "critical": 0}
    for a in alerts:
        sev = a["severity"]
        if sev in severity_summary:
            severity_summary[sev] += 1

    # Verdict logic
    if not alerts:
        verdict = "no_alert"
    elif severity_summary["critical"] > 0:
        verdict = "attack"
    else:
        verdict = "suspicious"

    return {
        "scenario": scenario_num,
        "alerts": alerts,
        "alert_count": len(alerts),
        "rules_triggered": rules_triggered,
        "severity_summary": severity_summary,
        "verdict": verdict,
    }


def evaluate_all() -> dict:
    """Run all scenarios and save results to data/normalized/."""
    scenario_files = sorted((PROJECT_ROOT / "data" / "scenarios").glob("scenario_*.json"))
    scenario_nums = [int(f.stem.split("_")[1]) for f in scenario_files]

    results = {}
    for scenario_num in scenario_nums:
        result = evaluate_scenario(scenario_num)
        results[f"scenario_{scenario_num}"] = result

        output_path = (
            PROJECT_ROOT
            / "data"
            / "normalized"
            / f"scenario_{scenario_num}_rule_results.json"
        )
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)
        logger.info("Saved: %s", output_path)

    return results


if __name__ == "__main__":
    print("=" * 70)
    print("FORENSIC FRAMEWORK - Rule Engine Evaluation")
    print("=" * 70)

    all_results = evaluate_all()

    for key, result in all_results.items():
        print(f"\n{'─' * 70}")
        print(f"  {key.upper()}")
        print(f"{'─' * 70}")
        print(f"  Verdict      : {result['verdict']}")
        print(f"  Alert count  : {result['alert_count']}")
        print(f"  Rules fired  : {result['rules_triggered']}")
        print(f"  Severity     : {result['severity_summary']}")
        if result["alerts"]:
            print(f"  Alerts:")
            for alert in result["alerts"]:
                print(
                    f"    [{alert['severity'].upper():8s}] {alert['rule_id']} "
                    f"{alert['rule_name']}: {alert['description']}"
                )

    print(f"\n{'=' * 70}")
    print("Evaluation complete.")
