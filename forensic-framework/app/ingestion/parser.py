"""
Parser — reads raw log files produced by log_generator and returns them as
Python dicts for downstream normalisation and analysis.
"""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RAW_LOGS_DIR = PROJECT_ROOT / "data" / "raw_logs"


def _load_json(filepath: Path) -> list[dict]:
    """Load a JSON file and return its contents as a list of dicts."""
    filepath = Path(filepath)
    if not filepath.exists():
        return []
    with open(filepath, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return [data]


def parse_auth_logs(filepath: str | Path) -> list[dict]:
    """Parse an auth raw log file and return a list of auth event dicts."""
    return _load_json(Path(filepath))


def parse_file_logs(filepath: str | Path) -> list[dict]:
    """Parse a file-access raw log file and return a list of file event dicts."""
    return _load_json(Path(filepath))


def parse_admin_logs(filepath: str | Path) -> list[dict]:
    """Parse an admin raw log file and return a list of admin event dicts."""
    return _load_json(Path(filepath))


def parse_network_logs(filepath: str | Path) -> list[dict]:
    """Parse a network raw log file and return a list of network event dicts."""
    return _load_json(Path(filepath))


def parse_db_logs(filepath: str | Path) -> list[dict]:
    """Parse a database raw log file and return a list of database event dicts."""
    return _load_json(Path(filepath))


def parse_web_logs(filepath: str | Path) -> list[dict]:
    """Parse a web server raw log file and return a list of web event dicts."""
    return _load_json(Path(filepath))


def parse_email_logs(filepath: str | Path) -> list[dict]:
    """Parse an email raw log file and return a list of email event dicts."""
    return _load_json(Path(filepath))


def parse_scenario(scenario_num: int | str) -> dict[str, list[dict]]:
    """Read all log types for a given scenario number.

    Returns {"auth": [...], "file": [...], "admin": [...], "network": [...],
             "db": [...], "web": [...], "email": [...]}.
    Missing files are represented as empty lists.
    """
    num = str(scenario_num)
    return {
        "auth": parse_auth_logs(RAW_LOGS_DIR / f"scenario_{num}_auth_logs.json"),
        "file": parse_file_logs(RAW_LOGS_DIR / f"scenario_{num}_file_logs.json"),
        "admin": parse_admin_logs(RAW_LOGS_DIR / f"scenario_{num}_admin_logs.json"),
        "network": parse_network_logs(RAW_LOGS_DIR / f"scenario_{num}_network_logs.json"),
        "db": parse_db_logs(RAW_LOGS_DIR / f"scenario_{num}_db_logs.json"),
        "web": parse_web_logs(RAW_LOGS_DIR / f"scenario_{num}_web_logs.json"),
        "email": parse_email_logs(RAW_LOGS_DIR / f"scenario_{num}_email_logs.json"),
    }


def parse_all_scenarios() -> dict[str, dict[str, list[dict]]]:
    """Discover and parse all scenarios present in the raw_logs directory.

    Returns a dict keyed by scenario number (string), each value being the
    output of parse_scenario() for that number.
    """
    if not RAW_LOGS_DIR.exists():
        return {}

    # Discover scenario numbers from filenames
    scenario_nums: set[str] = set()
    for path in RAW_LOGS_DIR.glob("scenario_*_*_logs.json"):
        # Filename pattern: scenario_{num}_{type}_logs.json
        parts = path.stem.split("_")
        # parts example: ["scenario", "1", "auth", "logs"]
        if len(parts) >= 4:
            scenario_nums.add(parts[1])

    results: dict[str, dict[str, list[dict]]] = {}
    for num in sorted(scenario_nums):
        results[num] = parse_scenario(num)

    return results
