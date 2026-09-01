"""
OCSF (Open Cybersecurity Schema Framework) v1.1 mapping layer.
Maps unified events to OCSF format for interoperability.
"""

# OCSF category mapping
OCSF_CATEGORY_MAP = {
    "auth": {"category_uid": 3, "category_name": "Identity & Access Management"},
    "file_access": {"category_uid": 4, "category_name": "Discovery"},
    "admin": {"category_uid": 1, "category_name": "System Activity"},
}

# OCSF activity mapping
OCSF_ACTIVITY_MAP = {
    "login": {"activity_id": 1, "activity_name": "Logon"},
    "logout": {"activity_id": 2, "activity_name": "Logoff"},
    "login_failed": {"activity_id": 1, "activity_name": "Logon", "status_id": 2},
    "file_read": {"activity_id": 1, "activity_name": "Read"},
    "file_download": {"activity_id": 5, "activity_name": "Download"},
    "privilege_change": {"activity_id": 3, "activity_name": "Grant"},
    "log_delete": {"activity_id": 4, "activity_name": "Delete"},
}

def to_ocsf(event: dict) -> dict:
    """Convert a unified event to OCSF v1.1 format."""
    category = OCSF_CATEGORY_MAP.get(event.get("source_type"), {})
    activity = OCSF_ACTIVITY_MAP.get(event.get("action"), {})

    return {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "Forensic Framework", "vendor_name": "Research Prototype"}
        },
        "category_uid": category.get("category_uid", 0),
        "category_name": category.get("category_name", "Unknown"),
        "activity_id": activity.get("activity_id", 0),
        "activity_name": activity.get("activity_name", "Unknown"),
        "time_dt": event.get("timestamp"),
        "severity_id": {"info": 1, "warning": 3, "critical": 5}.get(event.get("severity"), 0),
        "status_id": 1 if event.get("status") == "success" else 2,
        "status": event.get("status", "unknown"),
        "principal": {
            "user": {"uid": event.get("user")},
            "ip": event.get("source_ip"),
            "session": {"uid": event.get("session_id")}
        },
        "resource": {"name": event.get("resource")},
        "event_uid": event.get("event_id"),
        "raw_data": event.get("metadata", {})
    }

# ECS (Elastic Common Schema) mapping
def to_ecs(event: dict) -> dict:
    """Convert a unified event to ECS 8.x format."""
    return {
        "@timestamp": event.get("timestamp"),
        "event": {
            "id": event.get("event_id"),
            "category": [event.get("source_type", "")],
            "action": event.get("action", ""),
            "outcome": event.get("status", ""),
            "severity": {"info": 0, "warning": 50, "critical": 100}.get(event.get("severity"), 0)
        },
        "user": {"id": event.get("user")},
        "source": {"ip": event.get("source_ip")},
        "file": {"path": event.get("resource")} if event.get("resource") else {},
        "session": {"id": event.get("session_id")}
    }

def convert_scenario_to_ocsf(events: list[dict]) -> list[dict]:
    """Convert a list of unified events to OCSF format."""
    return [to_ocsf(e) for e in events]

def convert_scenario_to_ecs(events: list[dict]) -> list[dict]:
    """Convert a list of unified events to ECS format."""
    return [to_ecs(e) for e in events]
