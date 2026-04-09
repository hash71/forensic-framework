"""
Normalizer — takes parsed raw logs (from the parser module) and normalizes
them into a unified event schema suitable for timeline reconstruction,
correlation, and forensic analysis.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("forensic.normalizer")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = PROJECT_ROOT / "data" / "normalized"

# ---------------------------------------------------------------------------
# Severity mappings per source type
# ---------------------------------------------------------------------------

AUTH_SEVERITY = {
    "login": "info",
    "logout": "info",
    "login_failed": "warning",
}

FILE_SEVERITY = {
    "file_read": "info",
    "file_download": "info",
    "file_delete": "warning",
}

ADMIN_SEVERITY = {
    "privilege_change": "warning",
    "log_delete": "critical",
    "config_change": "warning",
}

NETWORK_SEVERITY = {
    "firewall_block": "warning",
    "dns_query": "info",
    "firewall_allow": "info",
    "vpn_connect": "info",
}

DB_SEVERITY = {
    "db_login_failed": "warning",
    "db_export": "warning",
    "db_query": "info",
    "db_login": "info",
    "db_schema_change": "critical",
}

EMAIL_SEVERITY = {
    "mail_sent": "info",
    "mail_received": "info",
    "mail_forwarded": "info",
}


# ---------------------------------------------------------------------------
# Per-source normalizers
# ---------------------------------------------------------------------------

def normalize_auth_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw auth log entry into the unified event schema.

    Parameters
    ----------
    raw_event : dict
        Raw auth log with keys: timestamp, event_type, username, ip_address,
        result, session.
    event_counter : int
        Sequential counter used to build the event_id.
    scenario_id : str
        Identifier embedded in the event_id (e.g. "s1").

    Returns
    -------
    dict  — unified event
    """
    action = raw_event.get("event_type", "unknown")
    severity = AUTH_SEVERITY.get(action, "info")

    # Treat a failed login action that comes through as "login" with
    # result="failure" as a warning as well.
    if action == "login" and raw_event.get("result", "").lower() == "failure":
        severity = "warning"

    metadata: dict = {}
    # Strip private/ground-truth keys from metadata
    metadata = {k: v for k, v in metadata.items() if not k.startswith("_")}

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "auth",
        "user": raw_event.get("username"),
        "action": action,
        "resource": None,
        "source_ip": raw_event.get("ip_address"),
        "status": raw_event.get("result"),
        "session_id": raw_event.get("session"),
        "severity": severity,
        "metadata": metadata,
    }


def normalize_file_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw file-access log entry into the unified event schema.

    Parameters
    ----------
    raw_event : dict
        Raw file log with keys: timestamp, event_type, username, file_path,
        file_size_bytes (optional), ip_address, result, session.
    event_counter : int
        Sequential counter for event_id.
    scenario_id : str
        Identifier embedded in the event_id.

    Returns
    -------
    dict  — unified event
    """
    action = raw_event.get("event_type", "unknown")
    severity = FILE_SEVERITY.get(action, "info")

    metadata: dict = {}
    if "file_size_bytes" in raw_event and raw_event["file_size_bytes"] is not None:
        metadata["file_size_bytes"] = raw_event["file_size_bytes"]
    # Strip private/ground-truth keys from metadata
    metadata = {k: v for k, v in metadata.items() if not k.startswith("_")}

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "file_access",
        "user": raw_event.get("username"),
        "action": action,
        "resource": raw_event.get("file_path"),
        "source_ip": raw_event.get("ip_address"),
        "status": raw_event.get("result"),
        "session_id": raw_event.get("session"),
        "severity": severity,
        "metadata": metadata,
    }


def normalize_admin_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw admin log entry into the unified event schema.

    Parameters
    ----------
    raw_event : dict
        Raw admin log with keys: timestamp, event_type, username, target,
        detail, ip_address, result.
    event_counter : int
        Sequential counter for event_id.
    scenario_id : str
        Identifier embedded in the event_id.

    Returns
    -------
    dict  — unified event
    """
    action = raw_event.get("event_type", "unknown")
    severity = ADMIN_SEVERITY.get(action, "info")

    metadata: dict = {}
    if "detail" in raw_event and raw_event["detail"] is not None:
        metadata["detail"] = raw_event["detail"]
    # Strip private/ground-truth keys from metadata
    metadata = {k: v for k, v in metadata.items() if not k.startswith("_")}

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "admin",
        "user": raw_event.get("username"),
        "action": action,
        "resource": raw_event.get("target"),
        "source_ip": raw_event.get("ip_address"),
        "status": raw_event.get("result"),
        "session_id": None,
        "severity": severity,
        "metadata": metadata,
    }


# ---------------------------------------------------------------------------
# Scenario-level normalization
# ---------------------------------------------------------------------------

def normalize_network_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw network log entry into the unified event schema."""
    event_type = raw_event.get("event_type", "unknown")
    severity = NETWORK_SEVERITY.get(event_type, "info")

    metadata: dict = {}
    if raw_event.get("protocol"):
        metadata["protocol"] = raw_event["protocol"]
    if raw_event.get("dst_ip"):
        metadata["dst_ip"] = raw_event["dst_ip"]
    if raw_event.get("src_port"):
        metadata["src_port"] = raw_event["src_port"]
    if raw_event.get("dst_port"):
        metadata["dst_port"] = raw_event["dst_port"]
    if raw_event.get("rule_name"):
        metadata["rule_name"] = raw_event["rule_name"]
    if raw_event.get("bytes_transferred"):
        metadata["bytes_transferred"] = raw_event["bytes_transferred"]

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "network",
        "user": None,
        "action": raw_event.get("action", event_type),
        "resource": raw_event.get("dst_ip"),
        "source_ip": raw_event.get("src_ip"),
        "status": raw_event.get("action"),
        "session_id": None,
        "severity": severity,
        "metadata": metadata,
    }


def normalize_db_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw database log entry into the unified event schema."""
    event_type = raw_event.get("event_type", "unknown")
    severity = DB_SEVERITY.get(event_type, "info")

    metadata: dict = {}
    if raw_event.get("database"):
        metadata["database"] = raw_event["database"]
    if raw_event.get("rows_affected"):
        metadata["rows_affected"] = raw_event["rows_affected"]
    if raw_event.get("duration_ms"):
        metadata["duration_ms"] = raw_event["duration_ms"]

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "database",
        "user": raw_event.get("username"),
        "action": event_type,
        "resource": raw_event.get("query"),
        "source_ip": raw_event.get("src_ip"),
        "status": raw_event.get("result"),
        "session_id": None,
        "severity": severity,
        "metadata": metadata,
    }


def normalize_web_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw web server log entry into the unified event schema."""
    status_code = raw_event.get("status_code", 200)

    if isinstance(status_code, str) and status_code.isdigit():
        status_code = int(status_code)

    if isinstance(status_code, int):
        if status_code >= 500:
            severity = "warning"
        elif status_code in (401, 403):
            severity = "warning"
        else:
            severity = "info"
    else:
        severity = "info"

    action = "http_error" if isinstance(status_code, int) and status_code >= 400 else "http_request"

    metadata: dict = {}
    if raw_event.get("user_agent"):
        metadata["user_agent"] = raw_event["user_agent"]
    if raw_event.get("response_size"):
        metadata["response_size"] = raw_event["response_size"]
    if raw_event.get("duration_ms"):
        metadata["duration_ms"] = raw_event["duration_ms"]
    if raw_event.get("method"):
        metadata["method"] = raw_event["method"]
    metadata["status_code"] = status_code

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "web_server",
        "user": None,
        "action": action,
        "resource": raw_event.get("url"),
        "source_ip": raw_event.get("src_ip"),
        "status": str(status_code),
        "session_id": None,
        "severity": severity,
        "metadata": metadata,
    }


def normalize_email_event(raw_event: dict, event_counter: int, scenario_id: str = "s0") -> dict:
    """Normalize a raw email log entry into the unified event schema."""
    event_type = raw_event.get("event_type", "unknown")
    severity = EMAIL_SEVERITY.get(event_type, "info")

    metadata: dict = {}
    if raw_event.get("subject"):
        metadata["subject"] = raw_event["subject"]
    if raw_event.get("attachments"):
        metadata["attachments"] = raw_event["attachments"]
    if raw_event.get("attachment_size_bytes"):
        metadata["attachment_size_bytes"] = raw_event["attachment_size_bytes"]

    recipients = raw_event.get("recipients", [])
    if isinstance(recipients, list):
        resource = ", ".join(recipients)
    else:
        resource = str(recipients)

    return {
        "event_id": f"evt_{scenario_id}_{event_counter:03d}",
        "timestamp": raw_event.get("timestamp"),
        "source_type": "email",
        "user": raw_event.get("sender"),
        "action": event_type,
        "resource": resource,
        "source_ip": None,
        "status": raw_event.get("result"),
        "session_id": None,
        "severity": severity,
        "metadata": metadata,
    }


_NORMALIZER_FOR_TYPE = {
    "auth": normalize_auth_event,
    "file": normalize_file_event,
    "admin": normalize_admin_event,
    "network": normalize_network_event,
    "db": normalize_db_event,
    "web": normalize_web_event,
    "email": normalize_email_event,
}


def normalize_scenario(parsed_logs: dict, scenario_id: str) -> list[dict]:
    """Normalize all parsed raw logs for a single scenario.

    Parameters
    ----------
    parsed_logs : dict
        Mapping of log type to list of raw events, e.g.
        {"auth": [...], "file": [...], "admin": [...]}.
    scenario_id : str
        Short scenario identifier used in event IDs (e.g. "s1").

    Returns
    -------
    list[dict]  — unified events sorted by timestamp.
    """
    all_events: list[dict] = []

    for log_type, events in parsed_logs.items():
        normalizer = _NORMALIZER_FOR_TYPE.get(log_type)
        if normalizer is None:
            continue
        for raw_event in events:
            # Use a placeholder counter; we'll re-number after sorting
            all_events.append((raw_event.get("timestamp", ""), log_type, raw_event))

    # Sort by timestamp string (ISO-8601 sorts lexicographically)
    all_events.sort(key=lambda t: t[0] or "")

    unified: list[dict] = []
    for counter, (_ts, log_type, raw_event) in enumerate(all_events, start=1):
        normalizer = _NORMALIZER_FOR_TYPE[log_type]
        unified.append(normalizer(raw_event, counter, scenario_id))

    return unified


# ---------------------------------------------------------------------------
# Batch normalization across all scenarios
# ---------------------------------------------------------------------------

def normalize_all(all_parsed: dict) -> dict:
    """Normalize parsed logs for every scenario and persist to JSON.

    Parameters
    ----------
    all_parsed : dict
        Keyed by scenario number/string (e.g. "1"), each value is the
        parsed_logs dict {"auth": [...], "file": [...], "admin": [...]}.

    Returns
    -------
    dict  — keyed by scenario number, values are the list of unified events.
    """
    NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)

    results: dict[str, list[dict]] = {}

    for scenario_num, parsed_logs in sorted(all_parsed.items(), key=lambda kv: kv[0]):
        scenario_id = f"s{scenario_num}"
        unified = normalize_scenario(parsed_logs, scenario_id)

        out_path = NORMALIZED_DIR / f"scenario_{scenario_num}_events.json"
        with open(out_path, "w") as f:
            json.dump(unified, f, indent=2)

        results[scenario_num] = unified
        logger.info("Scenario %s: %d normalized events -> %s", scenario_num, len(unified), out_path.name)

    return results


# ---------------------------------------------------------------------------
# Standalone entry-point
# ---------------------------------------------------------------------------

def _parse_raw_logs() -> dict:
    """Load raw log JSON files and group them by scenario number.

    This acts as a lightweight stand-in parser: it reads each
    scenario_{N}_{type}_logs.json from data/raw_logs/ and returns a dict
    keyed by scenario number, each containing {"auth": [...], "file": [...],
    "admin": [...]}.
    """
    raw_logs_dir = PROJECT_ROOT / "data" / "raw_logs"
    all_parsed: dict[str, dict[str, list]] = {}

    if not raw_logs_dir.exists():
        logger.warning("Raw logs directory not found: %s", raw_logs_dir)
        return all_parsed

    for log_file in sorted(raw_logs_dir.glob("scenario_*_*_logs.json")):
        parts = log_file.stem.split("_")
        # Expected pattern: scenario_{N}_{type}_logs
        # e.g. scenario_1_auth_logs  ->  parts = ["scenario", "1", "auth", "logs"]
        if len(parts) < 4:
            continue
        scenario_num = parts[1]
        log_type = parts[2]  # auth, file, or admin

        with open(log_file, "r") as f:
            events = json.load(f)

        if scenario_num not in all_parsed:
            all_parsed[scenario_num] = {
                "auth": [], "file": [], "admin": [],
                "network": [], "db": [], "web": [], "email": [],
            }
        all_parsed[scenario_num].setdefault(log_type, []).extend(events)

    return all_parsed


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Try to use the proper parser module first; fall back to local helper
    # ------------------------------------------------------------------
    try:
        from app.ingestion.parser import parse_all_scenarios
        print("Using app.ingestion.parser to parse raw logs...")
        all_parsed = parse_all_scenarios()

        # If raw logs haven't been generated yet, do that first
        if not all_parsed:
            print("No raw logs found — generating from scenarios first...")
            from app.ingestion.log_generator import generate_all as gen_all
            gen_summary = gen_all()
            for sn, counts in gen_summary.items():
                print(f"  Generated scenario {sn}: {counts}")
            all_parsed = parse_all_scenarios()

        print()
    except (ImportError, ModuleNotFoundError, AttributeError):
        print("Parser module not available — falling back to built-in raw log reader.\n")

        # Make sure raw logs exist by running the generator first
        from app.ingestion.log_generator import generate_all as gen_all
        print("Generating raw logs from scenarios...")
        gen_summary = gen_all()
        for sn, counts in gen_summary.items():
            print(f"  Generated scenario {sn}: {counts}")
        print()

        all_parsed = _parse_raw_logs()

    if not all_parsed:
        print("No parsed data available. Exiting.")
        raise SystemExit(1)

    # Normalize
    print("Normalizing events...")
    results = normalize_all(all_parsed)
    print()

    # Summary
    for scenario_num, events in results.items():
        print(f"Scenario {scenario_num}: {len(events)} events")

    # Sample events from scenario 1 (or the first available)
    first_key = next(iter(results), None)
    if first_key and results[first_key]:
        sample = results[first_key][:3]
        print(f"\nSample events from scenario {first_key}:")
        print(json.dumps(sample, indent=2))
