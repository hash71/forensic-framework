"""CERT Insider Threat Test Dataset (r4.2) adapter.

Source dataset:
    https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
    doi:10.1184/R1/12841247

This adapter maps five CERT r4.2 streams onto the unified event schema used
elsewhere in the framework, builds per-user-month investigation windows
(ATTACK = labeled insider activity windows from answers/insiders.csv; BENIGN
= sampled from users absent from the answers file), and returns scenarios
the existing rule engine + LLM pipeline can score.

Field mapping (CERT r4.2 column order -> unified event):

    logon.csv  (id, date, user, pc, activity)
        source_type = "auth"
        action      = {"Logon": "login", "Logoff": "logout"}[activity]
        resource    = None
        source_ip   = "pc:" + pc
        status      = "success"
        metadata    = {"cert_event_type": "logon", "pc": pc}

    device.csv  (id, date, user, pc, activity)
        source_type = "admin"
        action      = "usb_connect" or "usb_disconnect"
        resource    = "device:" + pc
        source_ip   = "pc:" + pc
        metadata    = {"cert_event_type": "device", "pc": pc}

    file.csv  (id, date, user, pc, filename, activity)
        source_type = "file_access"
        action      = "file_copy"          (file events in r4.2 record copies
                                            to removable media)
        resource    = filename
        source_ip   = "pc:" + pc
        metadata    = {"cert_event_type": "file", "pc": pc,
                       "cert_activity": activity}

    email.csv  (id, date, user, pc, to, cc, bcc, from_addr, size,
                attachments, content)
        source_type = "email"
        action      = "mail_sent"
        resource    = from_addr
        source_ip   = "pc:" + pc
        metadata    = {"cert_event_type": "email", "pc": pc,
                       "recipients": to split by ';', "cc": ..., "bcc": ...,
                       "attachment_size_bytes": int(size),
                       "attachments": int(attachments)}

    http.csv  (id, date, user, pc, url, content)
        source_type = "web_server"
        action      = "http_request"
        resource    = url
        source_ip   = "pc:" + pc
        status      = "200"
        metadata    = {"cert_event_type": "http", "pc": pc,
                       "method": "GET"}

Ground truth comes from answers/insiders.csv inside the answers archive.
Each row gives (dataset, scenario_type, details_file, user, start, end) for
one labeled insider. For r4.2 we use only rows with dataset = "4.2"; the
"start" and "end" timestamps bound the malicious activity window.

Windowing strategy (per-user-month):

  ATTACK windows: one per labeled insider per active month. If an insider's
    active period spans multiple months, each calendar month becomes its
    own window. All events from that user in that month are included; if
    more than `max_events_per_window` events exist, structured downsampling
    keeps every admin/device/file event and uniformly thins logon/http/email
    per day.

  BENIGN windows: random user-months from users NOT in the answers file,
    matched to the ATTACK windows' event-count distribution. If the median
    event count of the BENIGN sample differs from ATTACK by more than 25 %
    the sample is rejected and the seeded RNG draws again (capped retries).

This adapter never fabricates events. If the r4.2 tarball is missing it
raises FileNotFoundError with the download URL.
"""

from __future__ import annotations

import bz2
import csv
import io
import random
import re
import statistics
import tarfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


TZ_UTC = timezone.utc

DEFAULT_CERT_DIR = Path("~/data/cert").expanduser()
TARBALL_NAME = "r4.2.tar.bz2"
ANSWERS_DIR_NAME = "answers"
INSIDERS_FILE = "insiders.csv"

# Files we want from the tarball (anything else is skipped during streaming).
WANTED_CSV = {"logon.csv", "device.csv", "file.csv", "email.csv", "http.csv"}


# ---------------------------------------------------------------------------
# Insider answers
# ---------------------------------------------------------------------------

def _parse_cert_timestamp(ts: str) -> datetime:
    """CERT stores timestamps as 'M/D/YYYY H:M:S' or 'MM/DD/YYYY HH:MM:SS'."""
    return datetime.strptime(ts.strip(), "%m/%d/%Y %H:%M:%S").replace(tzinfo=TZ_UTC)


def load_insiders(cert_dir: Path, release: str = "4.2") -> dict[str, dict]:
    """Return {user_id: {scenario, start, end, details_file}} for the release.

    Reads answers/insiders.csv. Caller must have already extracted the
    answers.tar.bz2 (or the load helper below does it for them).
    """
    path = cert_dir / ANSWERS_DIR_NAME / INSIDERS_FILE
    if not path.exists():
        raise FileNotFoundError(
            f"{path} missing. Extract answers.tar.bz2 first or call "
            f"`ensure_answers_extracted(cert_dir)`."
        )
    insiders: dict[str, dict] = {}
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["dataset"] != release:
                continue
            uid = row["user"].strip()
            entry = {
                "scenario": row["scenario"].strip(),
                "start": _parse_cert_timestamp(row["start"]),
                "end": _parse_cert_timestamp(row["end"]),
                "details_file": row["details"].strip(),
            }
            # If multi-month, keep the earliest start (rare but possible)
            if uid not in insiders or entry["start"] < insiders[uid]["start"]:
                insiders[uid] = entry
    return insiders


def ensure_answers_extracted(cert_dir: Path) -> None:
    """Extract answers.tar.bz2 into cert_dir/answers/ if not already there."""
    answers_dir = cert_dir / ANSWERS_DIR_NAME
    if (answers_dir / INSIDERS_FILE).exists():
        return
    archive = cert_dir / "answers.tar.bz2"
    if not archive.exists():
        raise FileNotFoundError(
            f"{archive} not found. Download from "
            f"https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247"
        )
    with tarfile.open(archive, "r:bz2") as tar:
        tar.extractall(cert_dir)


# ---------------------------------------------------------------------------
# Streaming the main tarball
# ---------------------------------------------------------------------------

def _csv_filename(member_name: str) -> str | None:
    """Return the WANTED_CSV basename if member is one we care about."""
    base = Path(member_name).name.lower()
    return base if base in WANTED_CSV else None


def _logon_to_unified(row: list[str], idx: int) -> dict | None:
    if len(row) < 5:
        return None
    _id, date, user, pc, activity = row[:5]
    act = activity.strip().lower()
    return {
        "event_id": f"cert_logon_{idx:08d}",
        "timestamp": _parse_cert_timestamp(date).isoformat(),
        "source_type": "auth",
        "user": user.strip(),
        "action": "login" if act == "logon" else "logout",
        "resource": None,
        "source_ip": f"pc:{pc.strip()}",
        "status": "success",
        "session_id": _make_session(user, pc, date),
        "severity": "info",
        "metadata": {"cert_event_type": "logon", "pc": pc.strip()},
    }


def _device_to_unified(row: list[str], idx: int) -> dict | None:
    if len(row) < 5:
        return None
    _id, date, user, pc, activity = row[:5]
    act = activity.strip().lower()
    if act not in ("connect", "disconnect"):
        return None
    return {
        "event_id": f"cert_device_{idx:08d}",
        "timestamp": _parse_cert_timestamp(date).isoformat(),
        "source_type": "admin",
        "user": user.strip(),
        "action": f"usb_{act}",
        "resource": f"device:{pc.strip()}",
        "source_ip": f"pc:{pc.strip()}",
        "status": "success",
        "session_id": _make_session(user, pc, date),
        "severity": "warning",
        "metadata": {"cert_event_type": "device", "pc": pc.strip()},
    }


def _file_to_unified(row: list[str], idx: int) -> dict | None:
    # r4.2 file.csv columns: id, date, user, pc, filename, [activity]
    if len(row) < 5:
        return None
    _id, date, user, pc, filename = row[:5]
    activity = row[5].strip() if len(row) > 5 else "copy"
    return {
        "event_id": f"cert_file_{idx:08d}",
        "timestamp": _parse_cert_timestamp(date).isoformat(),
        "source_type": "file_access",
        "user": user.strip(),
        "action": "file_copy",
        "resource": filename.strip(),
        "source_ip": f"pc:{pc.strip()}",
        "status": "success",
        "session_id": _make_session(user, pc, date),
        "severity": "warning",
        "metadata": {
            "cert_event_type": "file", "pc": pc.strip(),
            "cert_activity": activity,
        },
    }


def _email_to_unified(row: list[str], idx: int) -> dict | None:
    # email.csv: id, date, user, pc, to, cc, bcc, from, size, attachments, content
    if len(row) < 10:
        return None
    _id, date, user, pc, to, cc, bcc, from_addr, size, attachments = row[:10]
    try:
        size_int = int(size)
    except ValueError:
        size_int = 0
    try:
        att_int = int(attachments)
    except ValueError:
        att_int = 0
    return {
        "event_id": f"cert_email_{idx:08d}",
        "timestamp": _parse_cert_timestamp(date).isoformat(),
        "source_type": "email",
        "user": user.strip(),
        "action": "mail_sent",
        "resource": from_addr.strip(),
        "source_ip": f"pc:{pc.strip()}",
        "status": "success",
        "session_id": _make_session(user, pc, date),
        "severity": "info",
        "metadata": {
            "cert_event_type": "email", "pc": pc.strip(),
            "recipients": [r for r in to.split(";") if r],
            "cc": [r for r in cc.split(";") if r],
            "bcc": [r for r in bcc.split(";") if r],
            "attachment_size_bytes": size_int,
            "attachments": att_int,
        },
    }


def _http_to_unified(row: list[str], idx: int) -> dict | None:
    if len(row) < 5:
        return None
    _id, date, user, pc, url = row[:5]
    return {
        "event_id": f"cert_http_{idx:08d}",
        "timestamp": _parse_cert_timestamp(date).isoformat(),
        "source_type": "web_server",
        "user": user.strip(),
        "action": "http_request",
        "resource": url.strip(),
        "source_ip": f"pc:{pc.strip()}",
        "status": "200",
        "session_id": _make_session(user, pc, date),
        "severity": "info",
        "metadata": {
            "cert_event_type": "http", "pc": pc.strip(),
            "method": "GET",
        },
    }


_CSV_PARSERS = {
    "logon.csv": _logon_to_unified,
    "device.csv": _device_to_unified,
    "file.csv": _file_to_unified,
    "email.csv": _email_to_unified,
    "http.csv": _http_to_unified,
}


def _make_session(user: str, pc: str, date_str: str) -> str:
    """Stable session id from user + pc + date (YYYYMMDD)."""
    try:
        d = _parse_cert_timestamp(date_str).strftime("%Y%m%d")
    except Exception:
        d = "unknown"
    return f"cert_{user.strip()}_{pc.strip()}_{d}"


def stream_events_for_users(
    tarball: Path, target_users: set[str],
    month_filter: dict[str, set[str]] | None = None,
    progress: callable | None = None,
) -> dict[str, list[dict]]:
    """Stream-read the CERT tarball and collect events for `target_users`.

    Args:
        tarball: Path to r4.2.tar.bz2 (not extracted).
        target_users: User IDs we want events for; everything else dropped.
        month_filter: Optional {user_id: {"YYYY-MM", ...}} — keep only events
            from those user-months. Used to bound memory.
        progress: Optional callback(message: str).

    Returns:
        {user_id: [event dict, ...]} sorted by timestamp per user.
    """
    if not tarball.exists():
        raise FileNotFoundError(
            f"{tarball} not found. Download r4.2.tar.bz2 from "
            f"https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247"
        )
    by_user: dict[str, list[dict]] = defaultdict(list)
    target_users = set(target_users)
    monthly = month_filter or {}

    with tarfile.open(tarball, "r:bz2") as tar:
        for member in tar:
            base = _csv_filename(member.name)
            if base is None or not member.isfile():
                continue
            parser = _CSV_PARSERS[base]
            if progress:
                progress(f"  reading {member.name}")
            f = tar.extractfile(member)
            if f is None:
                continue
            reader = csv.reader(io.TextIOWrapper(
                f, encoding="utf-8", errors="replace", newline=""
            ))
            header = next(reader, None)   # discard
            idx = 0
            for row in reader:
                idx += 1
                if not row or len(row) < 4:
                    continue
                # Column 2 in r4.2 = user
                user = row[2].strip()
                if user not in target_users:
                    continue
                # Quick month gate before parsing the rest
                if monthly and user in monthly:
                    try:
                        ts = _parse_cert_timestamp(row[1])
                    except Exception:
                        continue
                    if f"{ts.year:04d}-{ts.month:02d}" not in monthly[user]:
                        continue
                evt = parser(row, idx)
                if evt is not None:
                    by_user[user].append(evt)
    # Sort each user's events
    for u in by_user:
        by_user[u].sort(key=lambda e: e["timestamp"])
    return dict(by_user)


# ---------------------------------------------------------------------------
# Window building (per-user-month)
# ---------------------------------------------------------------------------

def _month_key(dt: datetime) -> str:
    return f"{dt.year:04d}-{dt.month:02d}"


def _split_by_month(events: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        ts = datetime.fromisoformat(e["timestamp"])
        out[_month_key(ts)].append(e)
    return out


def _downsample_window(
    events: list[dict], max_events: int, rng: random.Random,
) -> tuple[list[dict], bool, int]:
    """Cap the event count by keeping admin/device/file fully and uniformly
    thinning logon/http/email per day to fit the cap.

    Returns: (downsampled_events, was_downsampled, original_count)
    """
    original = len(events)
    if original <= max_events:
        return events, False, original
    keep_kinds = {"admin", "file_access"}
    keep = [e for e in events if e["source_type"] in keep_kinds]
    rest = [e for e in events if e["source_type"] not in keep_kinds]
    budget = max(0, max_events - len(keep))
    if budget <= 0:
        # Keep can already exceed cap (rare). Truncate uniformly.
        idx = sorted(rng.sample(range(len(keep)), max_events))
        return [keep[i] for i in idx], True, original
    # Distribute budget uniformly over days, never exceeding `budget` total.
    by_day: dict[str, list[dict]] = defaultdict(list)
    for e in rest:
        d = e["timestamp"][:10]
        by_day[d].append(e)
    days = sorted(by_day)
    if not days:
        return keep, True, original
    thinned: list[dict] = []
    if budget >= len(days):
        # We have room for at least one per day; distribute proportionally.
        per_day = max(1, budget // len(days))
        for d in days:
            bucket = by_day[d]
            take = min(len(bucket), per_day, budget - len(thinned))
            if take <= 0:
                break
            if take >= len(bucket):
                thinned.extend(bucket)
            else:
                idx = sorted(rng.sample(range(len(bucket)), take))
                thinned.extend(bucket[i] for i in idx)
        # Top up uniformly if still under budget
        remaining = budget - len(thinned)
        if remaining > 0:
            kept_ids = {id(e) for e in thinned}
            leftover = [e for e in rest if id(e) not in kept_ids]
            if leftover:
                top = rng.sample(leftover, min(remaining, len(leftover)))
                thinned.extend(top)
    else:
        # Budget smaller than #days: uniform random sample across all rest.
        thinned = rng.sample(rest, budget)
    merged = keep + thinned
    merged.sort(key=lambda e: e["timestamp"])
    return merged, True, original


def _build_attack_windows(
    insiders: dict[str, dict], events_by_user: dict[str, list[dict]],
    n_target: int, max_events: int, rng: random.Random,
) -> list[dict]:
    """One window per insider per active month, capped at n_target."""
    # Build candidate (insider, month, events) triples
    candidates = []
    for uid, info in insiders.items():
        evts = events_by_user.get(uid, [])
        if not evts:
            continue
        active_months: set[str] = set()
        cur = info["start"]
        while cur <= info["end"]:
            active_months.add(_month_key(cur))
            # advance ~1 day
            cur = cur + timedelta(days=1)
        by_month = _split_by_month(evts)
        for m in sorted(active_months):
            month_evts = by_month.get(m, [])
            if month_evts:
                candidates.append((uid, m, month_evts, info))

    rng.shuffle(candidates)
    picked = candidates[:n_target]

    out = []
    for uid, m, events, info in picked:
        evs, ds, orig = _downsample_window(events, max_events, rng)
        out.append({
            "scenario_id": f"cert_attack_{uid}_{m.replace('-', '')}",
            "name": f"cert_attack_{uid}_{m}",
            "label": "ATTACK",
            "description": (
                f"CERT r4.2 labeled insider {uid} (scenario "
                f"r4.2-{info['scenario']}) during {m}. Active "
                f"{info['start'].date()} -- {info['end'].date()}. "
                f"{len(evs)} events ({'downsampled from ' + str(orig) if ds else 'full'})."
            ),
            "events": evs,
            "source": "cert",
            "ground_truth_user": uid,
            "ground_truth_scenario_type": info["scenario"],
            "month": m,
            "downsampled": ds,
            "original_event_count": orig,
        })
    return out


def _build_benign_windows(
    events_by_user: dict[str, list[dict]],
    insider_ids: set[str],
    attack_counts: list[int],
    n_target: int, max_events: int, rng: random.Random,
    resample_threshold_pct: int = 25, max_attempts: int = 8,
) -> list[dict]:
    """Sample BENIGN user-months with event count matched to attack windows."""
    if not attack_counts:
        return []
    attack_median = statistics.median(attack_counts)

    # All candidate (uid, month, events)
    benign_pool = []
    for uid, evts in events_by_user.items():
        if uid in insider_ids or not evts:
            continue
        by_month = _split_by_month(evts)
        for m, month_evts in by_month.items():
            if not month_evts:
                continue
            benign_pool.append((uid, m, month_evts))

    if not benign_pool:
        return []

    best_sample = None
    best_diff = float("inf")
    for attempt in range(max_attempts):
        rng.shuffle(benign_pool)
        sample = benign_pool[:n_target]
        sample_counts = [len(s[2]) for s in sample]
        if not sample_counts:
            continue
        med = statistics.median(sample_counts)
        diff_pct = abs(med - attack_median) / max(1, attack_median) * 100
        if diff_pct < best_diff:
            best_diff = diff_pct
            best_sample = sample
        if diff_pct <= resample_threshold_pct:
            break

    if best_sample is None:
        return []

    out = []
    for uid, m, events in best_sample:
        evs, ds, orig = _downsample_window(events, max_events, rng)
        out.append({
            "scenario_id": f"cert_benign_{uid}_{m.replace('-', '')}",
            "name": f"cert_benign_{uid}_{m}",
            "label": "BENIGN",
            "description": (
                f"CERT r4.2 non-insider user {uid} during {m}. {len(evs)} "
                f"events ({'downsampled from ' + str(orig) if ds else 'full'}). "
                f"Drawn from a pool matched against the attack-window event-"
                f"count distribution (median diff {best_diff:.1f}%)."
            ),
            "events": evs,
            "source": "cert",
            "ground_truth_user": None,
            "month": m,
            "downsampled": ds,
            "original_event_count": orig,
            "volume_match_pct_diff": best_diff,
        })
    return out


def _resolve_cert_dir(cert_dir: Path) -> Path:
    return Path(cert_dir).expanduser()


def load_scenarios(
    cert_dir: Path = DEFAULT_CERT_DIR,
    n_attack: int = 20, n_benign: int = 20,
    max_events_per_window: int = 220, seed: int = 42,
    release: str = "4.2",
    progress: callable | None = None,
) -> tuple[list[dict], dict]:
    """Build CERT investigation-window scenarios.

    Returns (scenarios, manifest).
    """
    cert_dir = _resolve_cert_dir(cert_dir)
    tarball = cert_dir / TARBALL_NAME
    if not tarball.exists():
        raise FileNotFoundError(
            f"{tarball} not found. Download r4.2.tar.bz2 from "
            f"https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247 "
            f"(figshare id 24856766) into {cert_dir}/."
        )
    ensure_answers_extracted(cert_dir)
    rng = random.Random(seed)
    insiders = load_insiders(cert_dir, release=release)
    if not insiders:
        raise RuntimeError(f"No insiders found for release {release}.")

    # Stage 1: pull all events for insiders (small set, full year).
    if progress:
        progress(f"stage 1: streaming insider events ({len(insiders)} users)")
    insider_events = stream_events_for_users(tarball, set(insiders))

    # Stage 2: choose benign user candidates by sampling user IDs from the
    # logon stream (skipping insiders), then pull their events too.
    if progress:
        progress("stage 2: sampling benign-user candidates from logon stream")
    benign_candidates = _sample_benign_user_pool(
        tarball, insider_ids=set(insiders), target_size=max(60, n_benign * 3),
        rng=rng,
    )
    if progress:
        progress(f"stage 3: streaming benign events ({len(benign_candidates)} users)")
    benign_events = stream_events_for_users(tarball, benign_candidates)

    # Combine
    events_by_user = {**insider_events, **benign_events}

    # Build windows
    attack = _build_attack_windows(
        insiders, insider_events, n_attack, max_events_per_window, rng,
    )
    benign = _build_benign_windows(
        events_by_user, set(insiders),
        attack_counts=[w["original_event_count"] for w in attack],
        n_target=n_benign,
        max_events=max_events_per_window, rng=rng,
    )
    scenarios = attack + benign

    manifest = {
        "release": release,
        "seed": seed,
        "max_events_per_window": max_events_per_window,
        "n_attack": len(attack),
        "n_benign": len(benign),
        "attack_original_counts": [w["original_event_count"] for w in attack],
        "benign_original_counts": [w["original_event_count"] for w in benign],
        "attack_median_count": (
            statistics.median(w["original_event_count"] for w in attack)
            if attack else 0
        ),
        "benign_median_count": (
            statistics.median(w["original_event_count"] for w in benign)
            if benign else 0
        ),
        "windows": [
            {
                "scenario_id": w["scenario_id"],
                "label": w["label"],
                "user": (w["ground_truth_user"]
                         if w["label"] == "ATTACK"
                         else w["name"].split("_")[2]),
                "month": w["month"],
                "scenario_type": w.get("ground_truth_scenario_type"),
                "event_count": len(w["events"]),
                "original_count": w["original_event_count"],
                "downsampled": w["downsampled"],
            }
            for w in scenarios
        ],
    }
    return scenarios, manifest


def _sample_benign_user_pool(
    tarball: Path, insider_ids: set[str], target_size: int,
    rng: random.Random,
) -> set[str]:
    """Scan logon.csv once and collect a deterministic random subset of
    non-insider user IDs."""
    seen: list[str] = []
    seen_set: set[str] = set()
    with tarfile.open(tarball, "r:bz2") as tar:
        for member in tar:
            if Path(member.name).name.lower() != "logon.csv" or not member.isfile():
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            reader = csv.reader(io.TextIOWrapper(
                f, encoding="utf-8", errors="replace", newline=""
            ))
            next(reader, None)
            for row in reader:
                if len(row) < 3:
                    continue
                uid = row[2].strip()
                if uid in insider_ids or uid in seen_set:
                    continue
                seen_set.add(uid)
                seen.append(uid)
            break   # one CSV is enough
    rng.shuffle(seen)
    return set(seen[:target_size])
