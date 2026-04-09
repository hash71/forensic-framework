"""
Log Generator — reads scenario JSON files and produces source-specific raw log
files that simulate what real cloud log sources would produce.
"""

import json
import logging
from pathlib import Path

logger = logging.getLogger("forensic.ingestion")

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SCENARIOS_DIR = PROJECT_ROOT / "data" / "scenarios"
RAW_LOGS_DIR = PROJECT_ROOT / "data" / "raw_logs"

# Maps source_type values to the log category they belong to
SOURCE_TYPE_MAP = {
    "auth": "auth",
    "file_access": "file",
    "admin": "admin",
    "network": "network",
    "database": "db",
    "web_server": "web",
    "email": "email",
}


def _transform_auth_event(event: dict) -> dict:
    """Transform a unified event into an auth-source raw log entry."""
    return {
        "timestamp": event["timestamp"],
        "event_type": event["action"],
        "username": event["user"],
        "ip_address": event["source_ip"],
        "result": event["status"],
        "session": event["session_id"],
    }


def _transform_file_event(event: dict) -> dict:
    """Transform a unified event into a file-access-source raw log entry."""
    entry = {
        "timestamp": event["timestamp"],
        "event_type": event["action"],
        "username": event["user"],
        "file_path": event["resource"],
        "ip_address": event["source_ip"],
        "result": event["status"],
        "session": event["session_id"],
    }
    # Include file_size_bytes only for download events when metadata provides it
    metadata = event.get("metadata", {}) or {}
    if event["action"] == "file_download" and "file_size_bytes" in metadata:
        entry["file_size_bytes"] = metadata["file_size_bytes"]
    return entry


def _transform_admin_event(event: dict) -> dict:
    """Transform a unified event into an admin-source raw log entry."""
    metadata = event.get("metadata", {}) or {}
    detail = metadata.get("detail", metadata.get("reason", json.dumps(metadata)))
    return {
        "timestamp": event["timestamp"],
        "event_type": event["action"],
        "username": event["user"],
        "target": event["resource"],
        "detail": detail,
        "ip_address": event["source_ip"],
        "result": event["status"],
    }


def _transform_network_event(event: dict) -> dict:
    """Transform a unified event into a network-source raw log entry."""
    metadata = event.get("metadata", {}) or {}
    return {
        "timestamp": event["timestamp"],
        "event_type": event["action"],
        "protocol": metadata.get("protocol", "tcp"),
        "src_ip": event["source_ip"],
        "dst_ip": metadata.get("dst_ip", event.get("resource", "")),
        "src_port": metadata.get("src_port", 0),
        "dst_port": metadata.get("dst_port", 0),
        "action": metadata.get("action", event.get("status", "allow")),
        "rule_name": metadata.get("rule_name", ""),
        "bytes_transferred": metadata.get("bytes_transferred", 0),
    }


def _transform_db_event(event: dict) -> dict:
    """Transform a unified event into a database-source raw log entry."""
    metadata = event.get("metadata", {}) or {}
    return {
        "timestamp": event["timestamp"],
        "event_type": event["action"],
        "username": event["user"],
        "database": metadata.get("database", ""),
        "query": metadata.get("query", event.get("resource", "")),
        "src_ip": event["source_ip"],
        "result": event["status"],
        "rows_affected": metadata.get("rows_affected", 0),
        "duration_ms": metadata.get("duration_ms", 0),
    }


def _transform_web_event(event: dict) -> dict:
    """Transform a unified event into a web-server-source raw log entry."""
    metadata = event.get("metadata", {}) or {}
    return {
        "timestamp": event["timestamp"],
        "method": metadata.get("method", "GET"),
        "url": event.get("resource", ""),
        "src_ip": event["source_ip"],
        "status_code": metadata.get("status_code", 200),
        "user_agent": metadata.get("user_agent", ""),
        "response_size": metadata.get("response_size", 0),
        "duration_ms": metadata.get("duration_ms", 0),
    }


def _transform_email_event(event: dict) -> dict:
    """Transform a unified event into an email-source raw log entry."""
    metadata = event.get("metadata", {}) or {}
    return {
        "timestamp": event["timestamp"],
        "event_type": event["action"],
        "sender": event["user"],
        "recipients": metadata.get("recipients", []),
        "subject": metadata.get("subject", ""),
        "attachments": metadata.get("attachments", []),
        "attachment_size_bytes": metadata.get("attachment_size_bytes", 0),
        "result": event["status"],
    }


TRANSFORMERS = {
    "auth": _transform_auth_event,
    "file": _transform_file_event,
    "admin": _transform_admin_event,
    "network": _transform_network_event,
    "db": _transform_db_event,
    "web": _transform_web_event,
    "email": _transform_email_event,
}


def _extract_scenario_number(filename: str) -> str:
    """Extract the scenario number/identifier from a filename like scenario_1.json."""
    stem = Path(filename).stem  # e.g. "scenario_1"
    parts = stem.split("_", 1)
    return parts[1] if len(parts) > 1 else stem


def generate_scenario(scenario_path: Path) -> dict:
    """Generate raw log files for a single scenario file.

    Returns a dict with counts per log type, e.g. {"auth": 5, "file": 3, "admin": 2}.
    """
    with open(scenario_path, "r") as f:
        scenario_data = json.load(f)

    events = scenario_data if isinstance(scenario_data, list) else scenario_data.get("events", [])

    scenario_num = _extract_scenario_number(scenario_path.name)

    # Bucket events by log category
    buckets: dict[str, list] = {
        "auth": [], "file": [], "admin": [],
        "network": [], "db": [], "web": [], "email": [],
    }

    for event in events:
        source_type = event.get("source_type", "")
        category = SOURCE_TYPE_MAP.get(source_type)
        if category and category in TRANSFORMERS:
            transformed = TRANSFORMERS[category](event)
            buckets[category].append(transformed)

    # Write each non-empty bucket to its own raw log file
    RAW_LOGS_DIR.mkdir(parents=True, exist_ok=True)
    counts = {}

    type_to_filename = {
        "auth": f"scenario_{scenario_num}_auth_logs.json",
        "file": f"scenario_{scenario_num}_file_logs.json",
        "admin": f"scenario_{scenario_num}_admin_logs.json",
        "network": f"scenario_{scenario_num}_network_logs.json",
        "db": f"scenario_{scenario_num}_db_logs.json",
        "web": f"scenario_{scenario_num}_web_logs.json",
        "email": f"scenario_{scenario_num}_email_logs.json",
    }

    for log_type, entries in buckets.items():
        if entries:
            out_path = RAW_LOGS_DIR / type_to_filename[log_type]
            with open(out_path, "w") as f:
                json.dump(entries, f, indent=2)
            counts[log_type] = len(entries)

    return counts


def generate_all() -> dict:
    """Process every scenario_*.json file and generate all raw log files.

    Returns a dict keyed by scenario number, each value being the per-type counts.
    """
    summary: dict[str, dict] = {}

    scenario_files = sorted(SCENARIOS_DIR.glob("scenario_*.json"))
    if not scenario_files:
        logger.warning("No scenario files found in %s", SCENARIOS_DIR)
        return summary

    for scenario_path in scenario_files:
        scenario_num = _extract_scenario_number(scenario_path.name)
        counts = generate_scenario(scenario_path)
        summary[scenario_num] = counts

    return summary


if __name__ == "__main__":
    results = generate_all()
    if not results:
        print("Nothing generated — no scenario files found.")
    else:
        total_events = 0
        for scenario_num, counts in results.items():
            scenario_total = sum(counts.values())
            total_events += scenario_total
            print(f"Scenario {scenario_num}: {scenario_total} events  {counts}")
        print(f"\nTotal: {total_events} events across {len(results)} scenario(s)")
