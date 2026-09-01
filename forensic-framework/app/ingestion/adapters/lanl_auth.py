"""LANL "Comprehensive, Multi-Source Cyber-Security Events" adapter.

Source dataset:
    https://csr.lanl.gov/data/cyber1/  (free, registration required)

This adapter maps the LANL `auth.txt` and `redteam.txt` files onto the unified
event schema used elsewhere in the framework, then bundles them into
investigation-window scenarios that the pipeline can score the same way it
scores the synthetic corpus.

Field mapping (`auth.txt` → unified event):
    LANL field                  Unified field
    -------------------------   --------------------------------
    time (seconds since 0)      timestamp  (epoch + offset)
    source_user@source_domain   user
    dest_computer               resource  ("host:<dest_computer>")
    source_computer             source_ip ("host:<source_computer>")
    auth_orientation            action    (LogOn -> login, LogOff -> logout)
    success/failure             status    ("success" | "failed")
    -                           source_type = "auth"
    -                           event_id  = "lanl_<idx>"

Red-team events (`redteam.txt`) are the ground-truth attacker activity. Each
red-team line is treated as the centre of an ATTACK investigation window:
all auth events with a timestamp within `--window-minutes` of the red-team
event become the scenario's events. BENIGN windows are sampled from segments
of `auth.txt` that contain no red-team events.

This module never fabricates data. If the LANL files are not present at the
given `--lanl-dir`, `load_scenarios` raises `FileNotFoundError`.

Usage (programmatic):

    from app.ingestion.adapters.lanl_auth import load_scenarios
    scenarios = load_scenarios(
        lanl_dir=Path("/data/lanl/cyber1"),
        n_attack=20, n_benign=20, window_minutes=10,
    )

Usage (driver):

    python run_real_data.py --source lanl --lanl-dir /data/lanl/cyber1 \
        --n-attack 20 --n-benign 20 --window-minutes 10
"""

from __future__ import annotations

import bisect
import csv
import gzip
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


TZ_UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=TZ_UTC)


@dataclass
class LanlAuthEvent:
    """Parsed auth.txt row.

    The LANL release counts seconds from time=1; we treat this as seconds
    since the dataset epoch and synthesize a timestamp by adding to a
    deterministic base date so the rule engine's timestamp parsing works.
    """
    time_s: int
    source_user: str
    dest_user: str
    source_computer: str
    dest_computer: str
    auth_type: str
    logon_type: str
    auth_orientation: str
    outcome: str


@dataclass
class LanlRedteamEvent:
    time_s: int
    user: str
    source_computer: str
    dest_computer: str


# ---------------------------------------------------------------------------
# Low-level readers
# ---------------------------------------------------------------------------

def _open_maybe_gz(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_auth(path: Path) -> Iterator[LanlAuthEvent]:
    """Yield parsed auth events from `auth.txt[.gz]`."""
    with _open_maybe_gz(path) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 9:
                continue
            try:
                t = int(row[0])
            except ValueError:
                continue
            yield LanlAuthEvent(
                time_s=t,
                source_user=row[1],
                dest_user=row[2],
                source_computer=row[3],
                dest_computer=row[4],
                auth_type=row[5],
                logon_type=row[6],
                auth_orientation=row[7],
                outcome=row[8].strip(),
            )


def iter_redteam(path: Path) -> Iterator[LanlRedteamEvent]:
    """Yield parsed red-team events from `redteam.txt[.gz]`."""
    with _open_maybe_gz(path) as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 4:
                continue
            try:
                t = int(row[0])
            except ValueError:
                continue
            yield LanlRedteamEvent(
                time_s=t, user=row[1],
                source_computer=row[2], dest_computer=row[3],
            )


# ---------------------------------------------------------------------------
# Mapping to unified schema
# ---------------------------------------------------------------------------

_ACTION_MAP = {
    "LogOn": "login", "Logon": "login",
    "LogOff": "logout", "Logoff": "logout",
}


def _to_unified(ev: LanlAuthEvent, idx: int,
                 base_date: datetime) -> dict:
    """Map one LANL auth event to the framework's unified schema."""
    ts = (base_date + timedelta(seconds=ev.time_s)).isoformat()
    return {
        "event_id": f"lanl_{idx:08d}",
        "timestamp": ts,
        "source_type": "auth",
        "user": ev.source_user,
        "action": _ACTION_MAP.get(ev.auth_orientation, "auth_event"),
        "resource": f"host:{ev.dest_computer}",
        "source_ip": f"host:{ev.source_computer}",
        "status": "success" if ev.outcome.lower().startswith("succ") else "failed",
        "session_id": f"lanl_session_{ev.source_user}_{ev.source_computer}",
        "severity": "info",
        "metadata": {
            "lanl_time_s": ev.time_s,
            "auth_type": ev.auth_type,
            "logon_type": ev.logon_type,
            "dest_user": ev.dest_user,
            "auth_orientation": ev.auth_orientation,
        },
    }


# ---------------------------------------------------------------------------
# Scenario assembly
# ---------------------------------------------------------------------------

def _load_redteam_index(redteam_path: Path) -> list[LanlRedteamEvent]:
    return sorted(iter_redteam(redteam_path), key=lambda r: r.time_s)


def _redteam_times(redteam: list[LanlRedteamEvent]) -> list[int]:
    return [r.time_s for r in redteam]


def _build_attack_windows(
    auth_path: Path, redteam: list[LanlRedteamEvent],
    n_attack: int, window_seconds: int, base_date: datetime,
    rng: random.Random,
) -> list[dict]:
    """Build ATTACK scenarios by collecting auth events around red-team events.

    Streaming: we scan auth.txt once. Each red-team event seeds an empty
    bucket; an auth event drops into all buckets whose centre is within
    ±window_seconds. Buckets remain open until we are past their late edge.
    """
    centres = sorted(rng.sample(redteam, k=min(n_attack, len(redteam))),
                      key=lambda r: r.time_s)
    if not centres:
        return []
    buckets: list[dict] = [
        {"centre": c, "events": [], "closed": False} for c in centres
    ]
    # Open buckets in time order; close once we are past late edge.
    next_open_idx = 0
    open_buckets: list[dict] = []

    for idx, ev in enumerate(iter_auth(auth_path)):
        # Open new buckets whose start is reached
        while (next_open_idx < len(buckets)
                and ev.time_s >= buckets[next_open_idx]["centre"].time_s - window_seconds):
            open_buckets.append(buckets[next_open_idx])
            next_open_idx += 1
        # Drop into all currently-open buckets
        still_open: list[dict] = []
        for b in open_buckets:
            late_edge = b["centre"].time_s + window_seconds
            if ev.time_s > late_edge:
                b["closed"] = True
                continue
            b["events"].append(_to_unified(ev, idx, base_date))
            still_open.append(b)
        open_buckets = still_open
        # Stop early if every bucket is closed and no more to open
        if (not open_buckets and next_open_idx >= len(buckets)):
            break

    scenarios = []
    for i, b in enumerate(buckets):
        if not b["events"]:
            continue
        c = b["centre"]
        scenarios.append({
            "scenario_id": f"lanl_attack_{i:03d}",
            "name": f"lanl_redteam_{c.user}_{c.time_s}",
            "label": "ATTACK",
            "description": (
                f"LANL red-team activity window around t={c.time_s} for "
                f"user {c.user} (source={c.source_computer}, "
                f"dest={c.dest_computer}). Window: "
                f"±{window_seconds // 60} minutes."
            ),
            "events": b["events"],
            "source": "lanl",
            "ground_truth_user": c.user,
            "ground_truth_dest": c.dest_computer,
        })
    return scenarios


def _build_benign_windows(
    auth_path: Path, redteam_times: list[int],
    n_benign: int, window_seconds: int, base_date: datetime,
    rng: random.Random,
) -> list[dict]:
    """Build BENIGN scenarios by sampling windows that contain no red-team events.

    First-pass approach: pick `n_benign` random times in the auth.txt range,
    reject any within ±window_seconds of a red-team event, and gather all
    auth events that fall inside the window.
    """
    # We need the auth time range. Quick scan for min/max.
    first = last = None
    for ev in iter_auth(auth_path):
        if first is None:
            first = ev.time_s
        last = ev.time_s
    if first is None or last is None:
        return []

    sorted_redteam = sorted(redteam_times)
    chosen: list[int] = []
    attempts = 0
    while len(chosen) < n_benign and attempts < n_benign * 50:
        attempts += 1
        t = rng.randint(first + window_seconds, last - window_seconds)
        # Reject if any red-team event within window
        idx = bisect.bisect_left(sorted_redteam, t - window_seconds)
        if idx < len(sorted_redteam) and sorted_redteam[idx] <= t + window_seconds:
            continue
        chosen.append(t)
    chosen.sort()

    # Streaming collection
    bucket_for_centre: dict[int, list] = {c: [] for c in chosen}
    open_buckets: list[tuple[int, list]] = []
    next_open_idx = 0
    centres = sorted(chosen)
    for idx, ev in enumerate(iter_auth(auth_path)):
        while (next_open_idx < len(centres)
                and ev.time_s >= centres[next_open_idx] - window_seconds):
            open_buckets.append((centres[next_open_idx],
                                  bucket_for_centre[centres[next_open_idx]]))
            next_open_idx += 1
        still: list[tuple[int, list]] = []
        for c, lst in open_buckets:
            if ev.time_s > c + window_seconds:
                continue
            lst.append(_to_unified(ev, idx, base_date))
            still.append((c, lst))
        open_buckets = still
        if not open_buckets and next_open_idx >= len(centres):
            break

    scenarios = []
    for i, c in enumerate(centres):
        evts = bucket_for_centre[c]
        if not evts:
            continue
        scenarios.append({
            "scenario_id": f"lanl_benign_{i:03d}",
            "name": f"lanl_benign_window_{c}",
            "label": "BENIGN",
            "description": (
                f"LANL window centred at t={c} with no overlapping red-team "
                f"activity. Window ±{window_seconds // 60} minutes."
            ),
            "events": evts,
            "source": "lanl",
            "ground_truth_user": None,
        })
    return scenarios


def load_scenarios(
    lanl_dir: Path, n_attack: int = 20, n_benign: int = 20,
    window_minutes: int = 10, seed: int = 42,
    base_date: datetime | None = None,
) -> list[dict]:
    """Load `n_attack` ATTACK + `n_benign` BENIGN scenarios from LANL data.

    Args:
        lanl_dir: Directory containing `auth.txt[.gz]` and `redteam.txt[.gz]`.
        n_attack: Number of red-team-centred attack windows to sample.
        n_benign: Number of benign-period windows to sample (matched length).
        window_minutes: Half-width of each investigation window.
        seed: RNG seed for reproducible sampling.
        base_date: Synthetic base date for timestamp synthesis. Default
            2010-01-01 UTC.

    Raises:
        FileNotFoundError: If `auth.txt` or `redteam.txt` (or .gz variants)
            are not present.
    """
    auth_path = _resolve(lanl_dir, "auth.txt")
    redteam_path = _resolve(lanl_dir, "redteam.txt")

    if base_date is None:
        base_date = datetime(2010, 1, 1, tzinfo=TZ_UTC)

    rng = random.Random(seed)
    window_seconds = window_minutes * 60

    redteam = _load_redteam_index(redteam_path)
    attack_scenarios = _build_attack_windows(
        auth_path, redteam, n_attack, window_seconds, base_date, rng,
    )
    benign_scenarios = _build_benign_windows(
        auth_path, [r.time_s for r in redteam], n_benign,
        window_seconds, base_date, rng,
    )
    return attack_scenarios + benign_scenarios


def _resolve(directory: Path, basename: str) -> Path:
    """Return either `basename` or `basename + '.gz'` from `directory`."""
    candidate = directory / basename
    gz = directory / f"{basename}.gz"
    if candidate.exists():
        return candidate
    if gz.exists():
        return gz
    raise FileNotFoundError(
        f"Neither {candidate} nor {gz} exists. Download the LANL "
        f"Comprehensive, Multi-Source Cyber-Security Events dataset from "
        f"https://csr.lanl.gov/data/cyber1/ and place "
        f"auth.txt(.gz) and redteam.txt(.gz) in {directory}."
    )
