"""Scenario factory.

Parameter-driven, seeded generators that produce forensic scenarios in the
same on-disk schema as the hand-authored scenarios 1-15. Used to scale the
corpus from 15 to 115 for statistically powered evaluation.

Design constraints (anti-designer-bias controls):

1. All parameters come from `config/corpus_spec.yaml` (committed and
   auditable). Generators draw from a seeded `random.Random` instance.
2. Generated scenarios are flagged `holdout: true` in the corpus manifest.
   The LLM prompt (`app/llm/prompts.py`) was calibrated on scenarios 1-15
   only, so holdout-only metrics are the headline.
3. Each family declares its `label` and `hard_benign` flag in the spec.
   Generators must respect those — a `BENIGN` family must never produce
   genuine attack evidence; a `hard_benign` family must produce enough
   alert-worthy noise for false positives to be measurable.

Schema produced per scenario file:

    {
      "scenario_id": "scenario_N",
      "name": "<family>_<index>",
      "label": "BENIGN" | "ATTACK",
      "description": "...",
      "events": [ {event_id, timestamp, source_type, user, action,
                   resource, source_ip, status, session_id, severity,
                   metadata}, ... ]
    }

Ground-truth entries appended per scenario carry: id, name, label,
attacker, attack_steps, expected_detection, holdout, family, hard_benign.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
SPEC_PATH = PROJECT_ROOT / "config" / "corpus_spec.yaml"
TZ = timezone(timedelta(hours=6))   # Asia/Dhaka, matches existing scenarios


# ---------------------------------------------------------------------------
# Persona generation
# ---------------------------------------------------------------------------

_PERSONA_TEMPLATES = {
    "user_05": {
        "department": "sales",
        "role": "account_executive",
        "normal_hours": "09:00-18:00",
        "normal_directories": ["/data/sales/"],
        "avg_files_per_day": 6,
        "avg_downloads_per_day": 2,
    },
    "user_06": {
        "department": "devops",
        "role": "site_reliability_engineer",
        "normal_hours": "08:00-20:00",
        "normal_directories": ["/data/devops/", "/data/shared/runbooks/"],
        "avg_files_per_day": 12,
        "avg_downloads_per_day": 4,
        "maintenance_role": True,
    },
    "user_07": {
        "department": "security",
        "role": "security_analyst",
        "normal_hours": "09:00-18:00",
        "normal_directories": ["/data/security/", "/data/logs/"],
        "avg_files_per_day": 10,
        "avg_downloads_per_day": 3,
    },
    "user_08": {
        "department": "legal",
        "role": "corporate_counsel",
        "normal_hours": "09:00-17:30",
        "normal_directories": ["/data/legal/"],
        "avg_files_per_day": 5,
        "avg_downloads_per_day": 1,
    },
    "user_09": {
        "department": "marketing",
        "role": "marketing_manager",
        "normal_hours": "09:30-18:30",
        "normal_directories": ["/data/marketing/"],
        "avg_files_per_day": 7,
        "avg_downloads_per_day": 2,
    },
    "user_10": {
        "department": "executive",
        "role": "vp_operations",
        "normal_hours": "08:00-19:00",
        "normal_directories": [
            "/data/executive/", "/data/finance/", "/data/sales/",
        ],
        "avg_files_per_day": 6,
        "avg_downloads_per_day": 2,
        "access_level": "executive_read",
    },
}


def build_generated_personas(spec: dict) -> dict:
    """Return the dict of generator-created personas, keyed by user id.

    Deterministic — does not depend on RNG state, only on the spec.
    """
    persona_spec = spec["personas"]
    prefix = persona_spec["ip_prefix"]
    offset = persona_spec["ip_offset"]
    personas = {}
    for i, uid in enumerate(persona_spec["generated_ids"]):
        base = dict(_PERSONA_TEMPLATES[uid])
        base["timezone"] = "Asia/Dhaka"
        base["normal_ips"] = [f"{prefix}{offset + i}"]
        personas[uid] = base
    return personas


# ---------------------------------------------------------------------------
# Event helpers
# ---------------------------------------------------------------------------

@dataclass
class EventBuilder:
    """Stateful event builder that emits unified-schema events.

    Tracks the per-scenario event counter so event_ids are dense and
    deterministic: evt_s{N}_001, evt_s{N}_002, ...
    """

    scenario_num: int
    _counter: int = 0
    _events: list = None

    def __post_init__(self) -> None:
        if self._events is None:
            self._events = []

    def _next_id(self) -> str:
        self._counter += 1
        return f"evt_s{self.scenario_num}_{self._counter:03d}"

    def add(
        self,
        timestamp: datetime,
        source_type: str,
        user: str,
        action: str,
        source_ip: str,
        session_id: str | None = None,
        resource: str | None = None,
        status: str = "success",
        severity: str = "info",
        metadata: dict | None = None,
    ) -> dict:
        """Append one unified event and return it."""
        evt = {
            "event_id": self._next_id(),
            "timestamp": _iso(timestamp),
            "source_type": source_type,
            "user": user,
            "action": action,
            "resource": resource,
            "source_ip": source_ip,
            "status": status,
            "session_id": session_id,
            "severity": severity,
            "metadata": metadata or {},
        }
        self._events.append(evt)
        return evt

    @property
    def events(self) -> list[dict]:
        return self._events


def _iso(dt: datetime) -> str:
    """Serialize a TZ-aware datetime in the canonical +06:00 form."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt.isoformat()


def _session_id(user: str, day: datetime, n: int) -> str:
    """Session identifier matching the existing scenarios' style."""
    return f"sess_{user}_{day.strftime('%Y%m%d')}_{n:03d}"


def _normal_hours_window(persona: dict) -> tuple[int, int]:
    """Return (start_minute, end_minute) for a persona's working hours."""
    start_s, end_s = persona["normal_hours"].split("-")
    sh, sm = map(int, start_s.split(":"))
    eh, em = map(int, end_s.split(":"))
    return sh * 60 + sm, eh * 60 + em


def _random_time_in_window(
    rng: random.Random, day: datetime, persona: dict
) -> datetime:
    """Random datetime on `day` falling inside the persona's normal hours."""
    start_min, end_min = _normal_hours_window(persona)
    minute = rng.randrange(start_min, end_min)
    return day.replace(
        hour=minute // 60, minute=minute % 60,
        second=rng.randrange(60), microsecond=0,
    )


def _normal_ip(persona: dict) -> str:
    return persona["normal_ips"][0]


def _pick_resource(
    rng: random.Random, persona: dict, *, cross_department: bool = False,
    all_baselines: dict | None = None,
) -> str:
    """Pick a file resource path. Cross-department picks from another persona."""
    if cross_department and all_baselines:
        others = [
            u for u, b in all_baselines.items()
            if u != _persona_user_id(persona, all_baselines)
            and b.get("normal_directories")
        ]
        if others:
            other_id = rng.choice(others)
            other_dirs = all_baselines[other_id]["normal_directories"]
            directory = rng.choice(other_dirs)
        else:
            directory = rng.choice(persona["normal_directories"])
    else:
        directory = rng.choice(persona["normal_directories"])
    filename = _random_filename(rng, directory)
    return directory.rstrip("/") + "/" + filename


def _persona_user_id(persona: dict, all_baselines: dict) -> str:
    for uid, b in all_baselines.items():
        if b is persona:
            return uid
    return ""


_FILE_STEMS = [
    "report", "summary", "draft", "review", "memo", "plan", "budget",
    "forecast", "audit", "config", "schema", "migration", "release_notes",
    "design", "spec", "rfc", "data_export", "agreement", "policy",
]
_FILE_EXTS = ["pdf", "xlsx", "docx", "csv", "pptx", "txt", "yaml", "json"]


def _random_filename(rng: random.Random, directory: str) -> str:
    stem = rng.choice(_FILE_STEMS)
    suffix = rng.randrange(1, 999)
    ext = rng.choice(_FILE_EXTS)
    return f"{stem}_{suffix}.{ext}"


def _pick_persona(
    rng: random.Random, all_baselines: dict, *, exclude: set[str] | None = None,
    role_hint: str | None = None,
) -> tuple[str, dict]:
    candidates = list(all_baselines.keys())
    if exclude:
        candidates = [c for c in candidates if c not in exclude]
    if role_hint == "maintenance":
        maintenance = [
            c for c in candidates
            if all_baselines[c].get("maintenance_role")
        ]
        if maintenance:
            candidates = maintenance
    uid = rng.choice(candidates)
    return uid, all_baselines[uid]


# ---------------------------------------------------------------------------
# Family generators
#
# Each generator returns (events, attack_steps, attacker, description) and is
# called with (rng, scenario_num, all_baselines, family_params). The driver
# wraps the result into the scenario file + ground-truth entry.
# ---------------------------------------------------------------------------

def gen_normal_baseline(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    user, persona = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    sess = _session_id(user, day, 1)
    ip = _normal_ip(persona)

    login_t = _random_time_in_window(rng, day, persona)
    eb.add(login_t, "auth", user, "login", ip, sess,
           severity="info",
           metadata={"auth_method": "password",
                     "user_agent": _random_ua(rng)})

    event_count = rng.randint(*params["events_per_day"])
    last_t = login_t
    for _ in range(event_count):
        last_t += timedelta(minutes=rng.randint(5, 90))
        if last_t.hour * 60 + last_t.minute > _normal_hours_window(persona)[1]:
            break
        resource = _pick_resource(rng, persona)
        action = rng.choice(["file_read", "file_read", "file_download"])
        eb.add(last_t, "file_access", user, action, ip, sess,
               resource=resource,
               metadata={"access_type": "read" if action == "file_read"
                         else "download",
                         "file_size_bytes": (rng.randint(50_000, 5_000_000)
                                              if action == "file_download"
                                              else None)})

    logout_t = last_t + timedelta(minutes=rng.randint(10, 60))
    eb.add(logout_t, "auth", user, "logout", ip, sess,
           metadata={"session_duration_minutes":
                     int((logout_t - login_t).total_seconds() // 60)})

    desc = (f"Normal daily activity for {persona['role']} ({user}). "
            f"All access within expected hours, expected IP, and expected "
            f"directories.")
    return eb.events, [], None, desc


def gen_travel_noise(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    user, persona = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    duration = rng.randint(*params["duration_days"])
    foreign_ip = rng.choice(params["foreign_ip_pool"])
    city = _ip_city(foreign_ip)

    for day_idx in range(duration):
        d = day + timedelta(days=day_idx)
        sess = _session_id(user, d, day_idx + 1)
        login_t = d.replace(hour=rng.randint(8, 10),
                            minute=rng.randint(0, 59), second=0)
        eb.add(login_t, "auth", user, "login", foreign_ip, sess,
               metadata={"auth_method": "password",
                         "geo_location": city,
                         "user_agent": _random_ua(rng),
                         "note": f"{city} hotel/conference network"})
        events_today = rng.randint(*params["events_per_day"])
        last_t = login_t
        for _ in range(events_today):
            last_t += timedelta(minutes=rng.randint(2, 25))
            if last_t.hour >= 22:
                break
            action = rng.choice(["file_read", "file_read", "file_read",
                                  "file_download"])
            resource = _pick_resource(rng, persona)
            eb.add(last_t, "file_access", user, action, foreign_ip, sess,
                   resource=resource,
                   metadata={"access_type": "read" if action == "file_read"
                             else "download",
                             "file_size_bytes":
                             rng.randint(100_000, 8_000_000)
                             if action == "file_download" else None})
        logout_t = last_t + timedelta(minutes=rng.randint(10, 120))
        eb.add(logout_t, "auth", user, "logout", foreign_ip, sess,
               metadata={"session_duration_minutes":
                         int((logout_t - login_t).total_seconds() // 60)})

    desc = (f"{persona['role']} ({user}) working from {city} during business "
            f"travel. High file-access volume across {duration} day(s) but "
            f"all activity is within authorized directories and projects.")
    return eb.events, [], None, desc


def gen_credential_compromise(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    victim_uid, victim = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    attacker_ip = rng.choice(params["foreign_ip_pool"])
    sess = _session_id(victim_uid, day, 1)
    base_t = day.replace(hour=rng.randint(1, 5),
                         minute=rng.randint(0, 59), second=0)

    failures = rng.randint(*params["failed_attempts"])
    last_t = base_t
    for _ in range(failures):
        eb.add(last_t, "auth", victim_uid, "login_failed",
               attacker_ip, status="failed",
               severity="warning",
               metadata={"auth_method": "password",
                         "user_agent": "curl/8.0.0"})
        last_t += timedelta(seconds=rng.randint(10, 90))

    breach_t = last_t + timedelta(seconds=rng.randint(30, 120))
    eb.add(breach_t, "auth", victim_uid, "login", attacker_ip, sess,
           severity="warning",
           metadata={"auth_method": "password",
                     "user_agent": "curl/8.0.0",
                     "note": "Successful login after multiple failures"})

    eb.add(breach_t + timedelta(minutes=2), "admin", victim_uid,
           "privilege_change", attacker_ip, sess,
           resource="role",
           severity="critical",
           metadata={"detail": "elevated to admin role"})

    dl_count = rng.randint(*params["downloads_after_breach"])
    last_t = breach_t + timedelta(minutes=5)
    for _ in range(dl_count):
        resource = _pick_resource(rng, victim,
                                  cross_department=rng.random() < 0.4,
                                  all_baselines=baselines)
        eb.add(last_t, "file_access", victim_uid, "file_download",
               attacker_ip, sess,
               resource=resource,
               metadata={"access_type": "download",
                         "file_size_bytes":
                         rng.randint(1_000_000, 50_000_000)})
        last_t += timedelta(seconds=rng.randint(20, 180))

    if params["include_log_deletion"]:
        eb.add(last_t + timedelta(minutes=2), "admin", victim_uid,
               "log_delete", attacker_ip, sess,
               resource="/var/log/auth.log",
               severity="critical",
               metadata={"detail": "auth log truncated"})

    eb.add(last_t + timedelta(minutes=5), "auth", victim_uid, "logout",
           attacker_ip, sess,
           metadata={"session_duration_minutes":
                     int((last_t - breach_t).total_seconds() // 60)})

    desc = (f"Credential compromise targeting {victim_uid}: {failures} failed "
            f"login attempts from a foreign IP followed by a successful login, "
            f"privilege escalation, bulk download, and log cleanup.")
    attack_steps = ["failed_login_spike", "login_unusual_ip",
                    "privilege_escalation", "bulk_file_download"]
    if params["include_log_deletion"]:
        attack_steps.append("log_deletion")
    return eb.events, attack_steps, f"external (using {victim_uid} credentials)", desc


def gen_scope_creep(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    user, persona = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day0 = _base_day(rng)
    duration = rng.randint(*params["duration_days"])
    ip = _normal_ip(persona)
    cross_ratio_min, cross_ratio_max = params["cross_dept_ratio"]

    for day_idx in range(duration):
        d = day0 + timedelta(days=day_idx)
        sess = _session_id(user, d, 1)
        login_t = _random_time_in_window(rng, d, persona)
        eb.add(login_t, "auth", user, "login", ip, sess,
               metadata={"auth_method": "password",
                         "user_agent": _random_ua(rng)})

        files_today = rng.randint(*params["files_per_day"])
        cross_ratio = (cross_ratio_min
                       + (cross_ratio_max - cross_ratio_min)
                       * day_idx / max(1, duration - 1))
        last_t = login_t
        for _ in range(files_today):
            last_t += timedelta(minutes=rng.randint(20, 90))
            cross_dept = rng.random() < cross_ratio
            resource = _pick_resource(rng, persona,
                                       cross_department=cross_dept,
                                       all_baselines=baselines)
            action = "file_download" if day_idx >= duration - 2 else "file_read"
            eb.add(last_t, "file_access", user, action, ip, sess,
                   resource=resource,
                   metadata={"access_type": "read" if action == "file_read"
                             else "download",
                             "file_size_bytes":
                             rng.randint(50_000, 2_000_000)
                             if action == "file_download" else None})

        logout_t = last_t + timedelta(minutes=rng.randint(10, 60))
        eb.add(logout_t, "auth", user, "logout", ip, sess,
               metadata={"session_duration_minutes":
                         int((logout_t - login_t).total_seconds() // 60)})

    desc = (f"Insider scope creep: {user} ({persona['role']}) gradually "
            f"expands cross-department access over {duration} days, "
            f"transitioning from reading to systematic downloading on the "
            f"final days.")
    return eb.events, [
        "minor_cross_department_access",
        "expanding_cross_department_access",
        "systematic_download_final_days",
    ], user, desc


def gen_session_hijack(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    user, persona = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    legit_ip = _normal_ip(persona)
    hijack_ip = rng.choice(params["foreign_ip_pool"])
    sess = _session_id(user, day, 1)

    login_t = _random_time_in_window(rng, day, persona)
    eb.add(login_t, "auth", user, "login", legit_ip, sess,
           metadata={"auth_method": "password",
                     "user_agent": _random_ua(rng)})

    session_minutes = rng.randint(*params["session_duration_min"])
    hijack_pct_lo, hijack_pct_hi = params["hijack_point_pct"]
    hijack_pct = rng.uniform(hijack_pct_lo, hijack_pct_hi)
    hijack_min = int(session_minutes * hijack_pct)

    # Legitimate pre-hijack activity
    last_t = login_t
    for _ in range(rng.randint(3, 6)):
        last_t += timedelta(minutes=rng.randint(5, 15))
        resource = _pick_resource(rng, persona)
        eb.add(last_t, "file_access", user, "file_read", legit_ip, sess,
               resource=resource,
               metadata={"access_type": "read"})

    # Hijack point — IP changes mid-session
    hijack_t = login_t + timedelta(minutes=hijack_min)
    eb.add(hijack_t, "file_access", user, "file_read", hijack_ip, sess,
           resource=_pick_resource(rng, persona, cross_department=True,
                                    all_baselines=baselines),
           severity="warning",
           metadata={"access_type": "read",
                     "note": "First event from new IP within same session"})

    last_t = hijack_t
    for _ in range(rng.randint(4, 10)):
        last_t += timedelta(minutes=rng.randint(2, 8))
        cross_resource = _pick_resource(rng, persona,
                                         cross_department=True,
                                         all_baselines=baselines)
        eb.add(last_t, "file_access", user, "file_download", hijack_ip, sess,
               resource=cross_resource,
               metadata={"access_type": "download",
                         "file_size_bytes":
                         rng.randint(500_000, 10_000_000)})

    eb.add(last_t + timedelta(minutes=5), "auth", user, "logout",
           hijack_ip, sess,
           metadata={"session_duration_minutes":
                     int((last_t - login_t).total_seconds() // 60)})

    desc = (f"Session hijack of {user}: legitimate login from {legit_ip} "
            f"followed by mid-session IP change to {hijack_ip} and "
            f"unauthorized cross-department downloads.")
    return eb.events, [
        "session_hijack_ip_change",
        "unauthorized_cross_department_access",
        "data_exfiltration",
    ], f"external (via compromised {user} session)", desc


def gen_maintenance_window(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    user, persona = _pick_persona(rng, baselines, role_hint="maintenance")
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    ip = _normal_ip(persona)
    ticket = f"OPS-{rng.randint(1000, 9999)}"

    # Maintenance starts after hours
    start_h = rng.randint(22, 23)
    base_t = day.replace(hour=start_h,
                         minute=rng.randint(0, 30), second=0)
    sess = _session_id(user, day, 1)

    eb.add(base_t, "auth", user, "login", ip, sess,
           metadata={"auth_method": "ssh_key",
                     "user_agent": "OpenSSH_9.3",
                     "note": f"Scheduled maintenance window, ticket={ticket}"})

    if params["include_privilege_change"]:
        eb.add(base_t + timedelta(minutes=2), "admin", user,
               "privilege_change", ip, sess,
               resource="role",
               severity="warning",
               metadata={"detail": "elevated for maintenance",
                         "ticket": ticket})

    # Bulk file operations within /data/devops/
    last_t = base_t + timedelta(minutes=5)
    for _ in range(rng.randint(8, 20)):
        last_t += timedelta(seconds=rng.randint(30, 180))
        resource = _pick_resource(rng, persona)
        eb.add(last_t, "file_access", user, "file_download", ip, sess,
               resource=resource,
               metadata={"access_type": "download",
                         "file_size_bytes": rng.randint(1_000_000,
                                                         100_000_000),
                         "ticket": ticket})

    if params["include_log_rotation"]:
        eb.add(last_t + timedelta(minutes=3), "admin", user,
               "log_delete", ip, sess,
               resource="/var/log/old_rotations/",
               severity="warning",
               metadata={"detail": "scheduled log rotation",
                         "ticket": ticket})

    eb.add(last_t + timedelta(minutes=10), "admin", user,
           "privilege_change", ip, sess,
           resource="role",
           metadata={"detail": "reverted to baseline",
                     "ticket": ticket})

    eb.add(last_t + timedelta(minutes=15), "auth", user, "logout", ip, sess,
           metadata={"session_duration_minutes":
                     int((last_t - base_t).total_seconds() // 60)})

    desc = (f"Scheduled maintenance window by {user} ({persona['role']}). "
            f"Ticket {ticket} authorizes the privilege change, bulk backup "
            f"download, and log rotation. Privileges are reverted at end of "
            f"window.")
    return eb.events, [], None, desc


def gen_failed_stuffing(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    victim_uid, _ = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    attacker_ip = rng.choice(params["foreign_ip_pool"])
    base_t = day.replace(hour=rng.randint(0, 5),
                         minute=rng.randint(0, 59), second=0)

    attempts = rng.randint(*params["failed_attempts"])
    last_t = base_t
    for _ in range(attempts):
        eb.add(last_t, "auth", victim_uid, "login_failed",
               attacker_ip, status="failed",
               severity="warning",
               metadata={"auth_method": "password",
                         "user_agent": "python-requests/2.31"})
        last_t += timedelta(seconds=rng.randint(2, 30))

    desc = (f"Credential stuffing attempt against {victim_uid}: {attempts} "
            f"failed login attempts from {attacker_ip}. No successful login "
            f"— attack did not breach the perimeter.")
    return eb.events, [], None, desc


def gen_multistage_infra(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    attacker_ip = rng.choice(params["attacker_ip_pool"])
    victim_uid, victim = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    base_t = day.replace(hour=rng.randint(2, 5),
                         minute=rng.randint(0, 59), second=0)
    sess = _session_id(victim_uid, day, 1)

    # 1. SQL injection probe (web_server, status 500, SQL keyword in URL)
    if params["include_sql_injection"]:
        for _ in range(rng.randint(3, 6)):
            eb.add(base_t, "web_server", None, "http_request",
                   attacker_ip, status="500",
                   resource="/api/items?id=1' UNION SELECT * FROM users--",
                   severity="critical",
                   metadata={"method": "GET", "status_code": 500,
                             "user_agent": "sqlmap/1.7",
                             "response_size": rng.randint(500, 2000),
                             "duration_ms": rng.randint(50, 300)})
            base_t += timedelta(seconds=rng.randint(2, 8))

    # 2. Successful login with stolen creds
    base_t += timedelta(minutes=rng.randint(3, 10))
    eb.add(base_t, "auth", victim_uid, "login", attacker_ip, sess,
           severity="warning",
           metadata={"auth_method": "password",
                     "user_agent": "curl/8.0.0"})

    # 3. Privilege escalation
    base_t += timedelta(minutes=2)
    eb.add(base_t, "admin", victim_uid, "privilege_change",
           attacker_ip, sess,
           resource="role",
           severity="critical",
           metadata={"detail": "elevated to dba"})

    # 4. Database exfiltration
    base_t += timedelta(minutes=1)
    eb.add(base_t, "database", victim_uid, "db_login", attacker_ip, sess,
           metadata={"database": "prod_main"})
    for _ in range(rng.randint(2, 5)):
        base_t += timedelta(seconds=rng.randint(20, 90))
        eb.add(base_t, "database", victim_uid, "db_query",
               attacker_ip, sess,
               metadata={"database": "prod_main",
                         "query": "SELECT * FROM customers LIMIT 100000",
                         "rows_affected": rng.randint(50_000, 500_000),
                         "duration_ms": rng.randint(500, 5000)})

    # 5. DNS tunnel exfil (>20 events to same domain within 5 min)
    if params["include_dns_tunnel"]:
        domain = f"x{rng.randint(1000, 9999)}.malicious-{rng.randint(1, 99)}.com"
        for _ in range(rng.randint(25, 45)):
            base_t += timedelta(seconds=rng.randint(2, 8))
            eb.add(base_t, "network", victim_uid, "dns_query",
                   attacker_ip, sess,
                   resource=domain,
                   severity="warning",
                   metadata={"protocol": "udp",
                             "dst_port": 53,
                             "bytes_transferred": rng.randint(200, 1500)})

    # 6. Data volume breach (sum of bytes > 100MB in 30 min)
    if params["include_data_volume_breach"]:
        for _ in range(rng.randint(5, 12)):
            base_t += timedelta(seconds=rng.randint(30, 90))
            eb.add(base_t, "network", victim_uid, "data_out",
                   attacker_ip, sess,
                   severity="warning",
                   metadata={"protocol": "tcp", "dst_port": 443,
                             "bytes_transferred":
                             rng.randint(15_000_000, 40_000_000)})

    # 7. Log cleanup
    base_t += timedelta(minutes=3)
    eb.add(base_t, "admin", victim_uid, "log_delete",
           attacker_ip, sess,
           resource="/var/log/auth.log",
           severity="critical",
           metadata={"detail": "auth log truncated"})

    desc = (f"Multi-stage infrastructure attack against {victim_uid}: SQL "
            f"injection probes, stolen-credential login, privilege "
            f"escalation, database exfiltration, DNS tunnel, large outbound "
            f"transfer, and log cleanup.")
    return eb.events, [
        "sql_injection_probe", "authentication_with_stolen_creds",
        "privilege_escalation", "database_exfiltration",
        "dns_tunnel_exfiltration", "data_exfiltration_volume",
        "log_deletion_cleanup",
    ], f"external (using {victim_uid} credentials)", desc


def gen_decoy_misdirection(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    decoy_pool = [u for u in params["decoy_user_pool"] if u in baselines]
    if not decoy_pool:
        decoy_pool = list(baselines.keys())[:1]
    decoy_uid = rng.choice(decoy_pool)
    decoy_persona = baselines[decoy_uid]
    real_uid, real_persona = _pick_persona(rng, baselines,
                                            exclude={decoy_uid})

    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    decoy_ip = "185.220.101.45"   # known-loud Tor exit; matches existing pool
    sess_decoy = _session_id(decoy_uid, day, 1)
    sess_real = _session_id(real_uid, day, 1)

    # --- LOUD DECOY ---
    base_t = day.replace(hour=10, minute=0, second=0)
    for _ in range(rng.randint(5, 9)):
        eb.add(base_t, "auth", decoy_uid, "login_failed", decoy_ip,
               status="failed",
               severity="warning",
               metadata={"auth_method": "password",
                         "user_agent": "curl/8.0.0"})
        base_t += timedelta(seconds=rng.randint(5, 30))

    base_t += timedelta(seconds=30)
    eb.add(base_t, "auth", decoy_uid, "login", decoy_ip, sess_decoy,
           severity="warning",
           metadata={"auth_method": "password",
                     "user_agent": "curl/8.0.0"})

    base_t += timedelta(minutes=2)
    eb.add(base_t, "admin", decoy_uid, "privilege_change",
           decoy_ip, sess_decoy,
           resource="role",
           severity="critical",
           metadata={"detail": "elevated"})

    for _ in range(rng.randint(10, 15)):
        base_t += timedelta(seconds=rng.randint(20, 60))
        eb.add(base_t, "file_access", decoy_uid, "file_download",
               decoy_ip, sess_decoy,
               resource=_pick_resource(rng, decoy_persona),
               metadata={"access_type": "download",
                         "file_size_bytes":
                         rng.randint(1_000_000, 5_000_000)})

    base_t += timedelta(minutes=2)
    eb.add(base_t, "admin", decoy_uid, "log_delete",
           decoy_ip, sess_decoy,
           resource="/var/log/auth.log",
           severity="critical",
           metadata={"detail": "log cleanup"})

    # --- QUIET REAL ATTACK on real_uid, low and slow, runs in parallel ---
    real_t = day.replace(hour=10, minute=15, second=0)
    eb.add(real_t, "auth", real_uid, "login",
           _normal_ip(real_persona), sess_real,
           metadata={"auth_method": "password",
                     "user_agent": _random_ua(rng)})
    for _ in range(rng.randint(4, 8)):
        real_t += timedelta(minutes=rng.randint(8, 25))
        # Quiet real attacker exfils source code / sensitive data
        eb.add(real_t, "file_access", real_uid, "file_download",
               _normal_ip(real_persona), sess_real,
               resource=_pick_resource(rng, real_persona,
                                        cross_department=True,
                                        all_baselines=baselines),
               metadata={"access_type": "download",
                         "file_size_bytes":
                         rng.randint(500_000, 3_000_000)})
    eb.add(real_t + timedelta(minutes=15), "auth", real_uid, "logout",
           _normal_ip(real_persona), sess_real,
           metadata={"session_duration_minutes":
                     int((real_t - day.replace(hour=10, minute=15, second=0))
                         .total_seconds() // 60)})

    desc = (f"Decoy misdirection: a loud noisy attack on {decoy_uid} (foreign "
            f"IP, failed-then-success login, privilege change, bulk download, "
            f"log cleanup) masks a parallel quiet attack on {real_uid} that "
            f"exfiltrates cross-department data through an internal IP. "
            f"Ground-truth attacker is {real_uid}.")
    return eb.events, [
        f"decoy_attack_{decoy_uid}",
        f"real_attack_{real_uid}_quiet_exfil",
        "cross_department_data_collection",
    ], f"coordinated external (decoy on {decoy_uid}, real attack on {real_uid})", desc


def gen_legitimate_peak(
    rng: random.Random, num: int, baselines: dict, params: dict,
) -> tuple[list[dict], list[str], str | None, str]:
    user, persona = _pick_persona(rng, baselines)
    eb = EventBuilder(scenario_num=num)
    day = _base_day(rng)
    ip = _normal_ip(persona)
    peak_type = rng.choice(params["peak_type"])
    ticket = f"FIN-{rng.randint(1000, 9999)}"
    sess = _session_id(user, day, 1)

    # Login at start of work day, work late into the night
    login_t = day.replace(hour=8, minute=rng.randint(0, 30), second=0)
    eb.add(login_t, "auth", user, "login", ip, sess,
           metadata={"auth_method": "password",
                     "user_agent": _random_ua(rng),
                     "note": f"{peak_type} period, ticket={ticket}"})

    file_count = rng.randint(*params["file_count"])
    last_t = login_t
    for _ in range(file_count):
        last_t += timedelta(minutes=rng.randint(2, 10))
        # Allow some cross-department reads with ticket cover
        cross = rng.random() < 0.25
        resource = _pick_resource(rng, persona,
                                   cross_department=cross,
                                   all_baselines=baselines)
        action = rng.choice(["file_read", "file_download", "file_download"])
        eb.add(last_t, "file_access", user, action, ip, sess,
               resource=resource,
               metadata={"access_type": "read" if action == "file_read"
                         else "download",
                         "file_size_bytes":
                         rng.randint(100_000, 8_000_000)
                         if action == "file_download" else None,
                         "ticket": ticket})

    # Logout very late
    logout_t = last_t + timedelta(minutes=rng.randint(15, 90))
    eb.add(logout_t, "auth", user, "logout", ip, sess,
           metadata={"session_duration_minutes":
                     int((logout_t - login_t).total_seconds() // 60)})

    desc = (f"Legitimate workload peak ({peak_type}) for {user} "
            f"({persona['role']}). Ticket {ticket} authorizes the high "
            f"file volume, late hours, and limited cross-department reads.")
    return eb.events, [], None, desc


FAMILY_GENERATORS: dict[str, Callable] = {
    "normal_baseline": gen_normal_baseline,
    "travel_noise": gen_travel_noise,
    "credential_compromise": gen_credential_compromise,
    "scope_creep": gen_scope_creep,
    "session_hijack": gen_session_hijack,
    "maintenance_window": gen_maintenance_window,
    "failed_stuffing": gen_failed_stuffing,
    "multistage_infra": gen_multistage_infra,
    "decoy_misdirection": gen_decoy_misdirection,
    "legitimate_peak": gen_legitimate_peak,
}


# ---------------------------------------------------------------------------
# Misc helpers shared by generators
# ---------------------------------------------------------------------------

_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
]


def _random_ua(rng: random.Random) -> str:
    return rng.choice(_UAS)


def _base_day(rng: random.Random) -> datetime:
    """A random workday inside a fixed window so timestamps stay realistic.

    All generated scenarios fall in Apr-Aug 2026 to roughly align with the
    existing 15 scenarios' Apr 2026 timestamps. The exact day is sampled.
    """
    start = datetime(2026, 4, 1, tzinfo=TZ)
    end = datetime(2026, 8, 31, tzinfo=TZ)
    delta_days = (end - start).days
    return start + timedelta(days=rng.randrange(delta_days))


def _ip_city(ip: str) -> str:
    return {
        "103.28.45.67": "Singapore",
        "151.101.65.69": "San Francisco",
        "78.46.150.40": "Frankfurt",
        "45.79.97.21": "Tokyo",
        "139.59.13.50": "London",
    }.get(ip, "remote")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_spec(spec_path: Path = SPEC_PATH) -> dict:
    """Load the corpus generation spec from YAML."""
    with open(spec_path, "r") as f:
        return yaml.safe_load(f)


def generate_scenario(
    family: str, scenario_num: int, rng: random.Random,
    all_baselines: dict, spec: dict,
) -> tuple[dict, dict, dict]:
    """Generate one scenario.

    Returns:
        (scenario_dict, ground_truth_entry, manifest_entry)
    """
    family_spec = spec["families"][family]
    params = family_spec["params"]
    label = family_spec["label"]
    hard_benign = family_spec["hard_benign"]

    generator = FAMILY_GENERATORS[family]
    events, attack_steps, attacker, description = generator(
        rng, scenario_num, all_baselines, params,
    )

    # Build scenario file
    scenario = {
        "scenario_id": f"scenario_{scenario_num}",
        "name": f"{family}_{scenario_num:03d}",
        "label": label,
        "description": description,
        "events": events,
    }

    # Build ground-truth entry
    if label == "ATTACK":
        if hard_benign:
            expected = {"rule_based": "false_positive",
                        "llm_assisted": "no_alert"}
        else:
            expected = {"rule_based": "partial",
                        "llm_assisted": "full_detection"}
    else:
        # BENIGN
        if hard_benign:
            expected = {"rule_based": "false_positive",
                        "llm_assisted": "no_alert"}
        else:
            expected = {"rule_based": "no_alert",
                        "llm_assisted": "no_alert"}

    gt = {
        "id": f"scenario_{scenario_num}",
        "name": f"{family}_{scenario_num:03d}",
        "label": label,
        "attacker": attacker,
        "attack_steps": attack_steps,
        "expected_detection": expected,
        "holdout": True,
        "family": family,
        "hard_benign": hard_benign,
    }

    manifest = {
        "scenario_id": f"scenario_{scenario_num}",
        "family": family,
        "label": label,
        "hard_benign": hard_benign,
        "holdout": True,
        "event_count": len(events),
        "seed": spec["seed"],
    }

    return scenario, gt, manifest
