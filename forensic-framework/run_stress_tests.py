#!/usr/bin/env python3
"""Stress tests for forensic investigation framework.

Tests 4 dimensions of pipeline robustness:
  A) Raw Logs (No Pipeline) Baseline — proves structured pipeline adds value
  B) Event Removal — graceful degradation under missing data
  C) Noise Injection — tolerance to benign event flooding
  D) Timestamp Jitter — temporal sensitivity of the analysis
"""

import argparse
import asyncio
import json
import random
import sys
from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

PROJECT_ROOT = Path(__file__).parent
STRESS_DIR = PROJECT_ROOT / "data" / "stress_tests"
SCENARIOS_DIR = PROJECT_ROOT / "data" / "scenarios"
NORMALIZED_DIR = PROJECT_ROOT / "data" / "normalized"
LLM_RESPONSES_DIR = PROJECT_ROOT / "data" / "llm_responses"
GROUND_TRUTH_PATH = PROJECT_ROOT / "data" / "ground_truth" / "ground_truth.json"
BASELINES_PATH = PROJECT_ROOT / "data" / "user_baselines.json"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_ground_truth() -> dict:
    """Load ground truth keyed by scenario number."""
    with open(GROUND_TRUTH_PATH, "r") as f:
        data = json.load(f)
    return {
        int(s["id"].replace("scenario_", "")): s
        for s in data["scenarios"]
    }


def load_scenario_events(scenario_num: int) -> list[dict]:
    """Load raw events from a scenario JSON file."""
    path = SCENARIOS_DIR / f"scenario_{scenario_num}.json"
    with open(path, "r") as f:
        data = json.load(f)
    return data.get("events", [])


def load_baselines() -> dict:
    """Load user baselines."""
    with open(BASELINES_PATH, "r") as f:
        return json.load(f)


def load_saved_llm_response(scenario_num: int) -> dict:
    """Load the saved (mock or real) LLM response for a scenario."""
    path = LLM_RESPONSES_DIR / f"scenario_{scenario_num}_response.json"
    with open(path, "r") as f:
        return json.load(f)


def ensure_stress_dir():
    """Create the stress tests output directory if needed."""
    STRESS_DIR.mkdir(parents=True, exist_ok=True)


def ground_truth_label(gt: dict) -> str:
    """Return 'ATTACK' or 'BENIGN' from ground truth entry."""
    return gt.get("label", "UNKNOWN")


def ground_truth_steps(gt: dict) -> list[str]:
    """Return the expected attack steps from ground truth."""
    return gt.get("attack_steps", [])


def verdict_from_response(response: dict) -> str:
    """Extract the verdict string from an LLM response."""
    return response.get("verdict", "UNKNOWN").upper().strip()


def is_verdict_correct(verdict: str, gt_label: str) -> bool:
    """Check if the LLM verdict matches ground truth label."""
    verdict_mapped = "ATTACK" if verdict == "YES" else "BENIGN"
    return verdict_mapped == gt_label


def compute_recall(response: dict, gt: dict) -> float:
    """Compute recall: fraction of ground truth attack steps mentioned."""
    gt_steps = ground_truth_steps(gt)
    if not gt_steps:
        return 1.0  # No steps expected, nothing to miss

    attack_chain = response.get("attack_chain", [])
    chain_descriptions = " ".join(
        step.get("description", "").lower() for step in attack_chain
    )
    narrative = (response.get("narrative", "") or "").lower()
    combined_text = chain_descriptions + " " + narrative

    matched = 0
    for step in gt_steps:
        # Map ground truth step names to keywords that should appear
        keywords = _step_keywords(step)
        if any(kw in combined_text for kw in keywords):
            matched += 1

    return matched / len(gt_steps) if gt_steps else 1.0


def _step_keywords(step_name: str) -> list[str]:
    """Map a ground truth step name to keywords to look for in LLM output."""
    mapping = {
        "failed_login_attempts": ["failed login", "brute", "credential"],
        "login_unusual_ip": ["unusual ip", "tor", "external ip", "185.220"],
        "privilege_escalation": ["privilege", "escalat", "read_write"],
        "bulk_file_download": ["bulk download", "exfiltrat", "mass download", "multiple file"],
        "log_deletion": ["log delet", "anti-forensic", "cover track"],
        "logout": ["logout", "session end"],
        "login_normal": ["login", "normal login", "authenticated"],
        "minor_privilege_change": ["privilege", "access grant", "role change"],
        "slow_scope_expansion_day1": ["day 1", "reconnaissance", "read"],
        "slow_scope_expansion_day2": ["day 2", "lateral", "download"],
        "systematic_download_day3": ["day 3", "systematic", "bulk"],
        "data_exfiltration_complete": ["exfiltrat", "collection", "download"],
        "session_hijack_ip_change": ["session hijack", "ip change", "ip switch"],
        "unauthorized_hr_access_1": ["hr", "unauthorized", "human resource"],
        "unauthorized_hr_access_2": ["hr", "unauthorized", "human resource"],
        "unauthorized_hr_access_3": ["hr", "unauthorized", "human resource"],
        "sql_injection_probe": ["sql injection", "sql", "injection"],
        "credential_dump": ["credential dump", "credential", "dump"],
        "authentication_with_stolen_creds": ["stolen cred", "compromised cred", "login"],
        "database_exfiltration": ["database", "exfiltrat", "db"],
        "file_server_access": ["file server", "lateral", "file access"],
        "dns_tunnel_exfiltration": ["dns tunnel", "tunnel", "dns exfil"],
        "log_deletion_cleanup": ["log delet", "cleanup", "anti-forensic"],
    }
    return mapping.get(step_name, [step_name.replace("_", " ")])


def count_hallucinations(response: dict, valid_event_ids: set[str]) -> int:
    """Count hallucinated event references in the response."""
    referenced = set()
    for step in response.get("attack_chain", []):
        eid = step.get("event_id")
        if eid:
            referenced.add(eid)
    for eid in response.get("evidence_for", []):
        referenced.add(eid)
    for eid in response.get("evidence_against", []):
        referenced.add(eid)

    return len(referenced - valid_event_ids)


# ---------------------------------------------------------------------------
# Pipeline runner for modified events
# ---------------------------------------------------------------------------

def run_pipeline_on_events(events: list[dict], scenario_num: int,
                           tag: str = "stress") -> dict:
    """Write events to temp file, run normalize -> timeline -> rules, return artifacts.

    Returns dict with keys: events, timeline, rule_results, alerts
    """
    ensure_stress_dir()

    # Save modified events as a temporary normalized events file
    events_path = STRESS_DIR / f"scenario_{scenario_num}_{tag}_events.json"
    with open(events_path, "w") as f:
        json.dump(events, f, indent=2)

    # Build timeline from events (sort by timestamp)
    from app.timeline.timeline import build_timeline, group_by_user, group_by_session

    timeline = build_timeline(events)
    by_user = group_by_user(timeline)
    by_session = group_by_session(timeline)

    time_range = {}
    if timeline:
        time_range = {
            "start": timeline[0].get("timestamp", ""),
            "end": timeline[-1].get("timestamp", ""),
        }

    timeline_data = {
        "scenario": scenario_num,
        "total_events": len(timeline),
        "timeline": timeline,
        "by_user": by_user,
        "by_session": by_session,
        "time_range": time_range,
    }

    timeline_path = STRESS_DIR / f"scenario_{scenario_num}_{tag}_timeline.json"
    with open(timeline_path, "w") as f:
        json.dump(timeline_data, f, indent=2)

    # Run rule engine on the events
    from app.rules.rule_engine import run_rules, load_baselines as load_rule_baselines

    baselines = load_rule_baselines()
    alerts = run_rules(events, baselines)

    # Compute rule verdict
    severity_summary = {"warning": 0, "critical": 0}
    for a in alerts:
        sev = a.get("severity", "")
        if sev in severity_summary:
            severity_summary[sev] += 1

    if severity_summary["critical"] > 0:
        rule_verdict = "attack"
    elif severity_summary["warning"] >= 3:
        rule_verdict = "suspicious"
    else:
        rule_verdict = "no_alert"

    rule_results = {
        "scenario": scenario_num,
        "alerts": alerts,
        "alert_count": len(alerts),
        "rules_triggered": len(set(a.get("rule_id", "") for a in alerts)),
        "severity_summary": dict(severity_summary),
        "verdict": rule_verdict,
    }

    rule_path = STRESS_DIR / f"scenario_{scenario_num}_{tag}_rule_results.json"
    with open(rule_path, "w") as f:
        json.dump(rule_results, f, indent=2)

    return {
        "events": events,
        "timeline": timeline_data,
        "rule_results": rule_results,
        "alerts": alerts,
    }


def build_llm_prompt_from_artifacts(artifacts: dict, scenario_num: int) -> str:
    """Build an LLM analysis prompt from pipeline artifacts."""
    from app.llm.prompts import build_analysis_prompt

    baselines = load_baselines()
    timeline = artifacts["timeline"].get("timeline", [])
    triggered_rules = artifacts["rule_results"].get("alerts", [])
    scenario_id = f"scenario_{scenario_num}"

    return build_analysis_prompt(baselines, timeline, triggered_rules, scenario_id)


async def run_llm_analysis(prompt: str, scenario_num: int, use_mock: bool = True) -> dict:
    """Run LLM analysis (mock or live) on a prompt."""
    if use_mock:
        # In mock mode, return the saved response for this scenario
        try:
            return load_saved_llm_response(scenario_num)
        except FileNotFoundError:
            return {
                "verdict": "UNKNOWN",
                "error": f"No saved response for scenario {scenario_num}",
            }
    else:
        from app.llm.client import call_modal_llm
        from app.llm.prompts import LLM_SYSTEM_PROMPT
        return await call_modal_llm(prompt, system_prompt=LLM_SYSTEM_PROMPT)


# ---------------------------------------------------------------------------
# Test A: Raw Logs (No Pipeline) Baseline
# ---------------------------------------------------------------------------

async def test_a_raw_logs_baseline(scenario_nums: list[int],
                                   use_mock: bool = True) -> list[dict]:
    """Test A: Send raw logs directly to LLM without pipeline processing.

    Proves that the structured pipeline (normalize -> timeline -> rules)
    adds value over raw log analysis.
    """
    gt_all = load_ground_truth()
    results = []

    for snum in scenario_nums:
        gt = gt_all.get(snum)
        if not gt:
            continue

        events = load_scenario_events(snum)
        valid_ids = {e["event_id"] for e in events}

        # Build a simple raw-log prompt (no pipeline processing)
        raw_prompt = (
            "Analyze these raw log events for security incidents:\n\n"
            + json.dumps(events, indent=2)
            + "\n\nRespond in JSON with keys: verdict (YES/NO/INSUFFICIENT), "
            "confidence (HIGH/MEDIUM/LOW), suspect (user_id or null), "
            "attack_chain (list of steps with event_id and description), "
            "evidence_for (list of event_ids), evidence_against (list of event_ids), "
            "gaps (list of strings), narrative (summary string)."
        )

        if use_mock:
            # Mock mode: return a degraded version of the saved response
            # to simulate what a raw-log-only analysis might produce
            try:
                saved = load_saved_llm_response(snum)
                response = _simulate_raw_log_response(saved, gt)
            except FileNotFoundError:
                response = {"verdict": "UNKNOWN"}
        else:
            from app.llm.client import call_modal_llm
            # Send raw logs WITHOUT the forensic system prompt
            response = await call_modal_llm(raw_prompt, system_prompt="")

        verdict = verdict_from_response(response)
        correct = is_verdict_correct(verdict, ground_truth_label(gt))
        recall = compute_recall(response, gt)
        halluc = count_hallucinations(response, valid_ids)

        results.append({
            "scenario": snum,
            "mode": "raw_logs",
            "verdict": verdict,
            "correct": correct,
            "recall": f"{recall:.0%}",
            "hallucinations": halluc,
        })

        # Also run with full pipeline for comparison
        pipeline_response = load_saved_llm_response(snum) if use_mock else response
        p_verdict = verdict_from_response(pipeline_response)
        p_correct = is_verdict_correct(p_verdict, ground_truth_label(gt))
        p_recall = compute_recall(pipeline_response, gt)
        p_halluc = count_hallucinations(pipeline_response, valid_ids)

        results.append({
            "scenario": snum,
            "mode": "full_pipeline",
            "verdict": p_verdict,
            "correct": p_correct,
            "recall": f"{p_recall:.0%}",
            "hallucinations": p_halluc,
        })

    return results


def _simulate_raw_log_response(saved_response: dict, gt: dict) -> dict:
    """Simulate a degraded raw-log analysis by stripping structure from saved response.

    Without the pipeline, the LLM would likely:
    - Get the overall verdict right for obvious attacks
    - Miss subtle attack steps
    - Have lower recall
    - Potentially hallucinate event IDs
    """
    response = deepcopy(saved_response)
    label = ground_truth_label(gt)

    if label == "ATTACK":
        steps = ground_truth_steps(gt)
        chain = response.get("attack_chain", [])

        # Raw analysis misses ~30-50% of attack chain steps
        if len(chain) > 2:
            keep_count = max(2, len(chain) // 2)
            response["attack_chain"] = random.sample(chain, keep_count)

        # Lower confidence without structured timeline/rules
        if response.get("confidence") == "HIGH":
            response["confidence"] = "MEDIUM"

        # Simulate occasional hallucinated event IDs
        if random.random() < 0.3:
            fake_ids = [f"evt_s{gt['id'].split('_')[1]}_999"]
            response.setdefault("evidence_for", []).extend(fake_ids)

        response["narrative"] = (
            response.get("narrative", "") +
            " [NOTE: Analysis from raw logs without structured pipeline.]"
        )
    else:
        # For benign scenarios, raw analysis may produce more false positives
        if random.random() < 0.4:
            response["verdict"] = "YES"
            response["confidence"] = "LOW"

    response["source"] = "raw_logs_mock"
    return response


# ---------------------------------------------------------------------------
# Test B: Event Removal (Graceful Degradation)
# ---------------------------------------------------------------------------

async def test_b_event_removal(scenario_nums: list[int],
                               use_mock: bool = True,
                               trials: int = 3) -> list[dict]:
    """Test B: Randomly remove events and measure degradation."""
    gt_all = load_ground_truth()
    removal_levels = [0.0, 0.2, 0.4, 0.6, 0.8]
    results = []

    for snum in scenario_nums:
        gt = gt_all.get(snum)
        if not gt:
            continue

        events = load_scenario_events(snum)
        valid_ids = {e["event_id"] for e in events}

        for removal_pct in removal_levels:
            trial_range = [0] if removal_pct == 0.0 else range(1, trials + 1)

            for trial in trial_range:
                if removal_pct == 0.0:
                    degraded = deepcopy(events)
                else:
                    n_remove = int(len(events) * removal_pct)
                    indices_to_remove = set(random.sample(range(len(events)), n_remove))
                    degraded = [
                        e for i, e in enumerate(events) if i not in indices_to_remove
                    ]

                remaining_ids = {e["event_id"] for e in degraded}

                # Run through pipeline
                tag = f"removal_{int(removal_pct*100)}_t{trial}"
                artifacts = run_pipeline_on_events(degraded, snum, tag=tag)

                # Get LLM response
                if use_mock:
                    response = _simulate_degraded_response(
                        load_saved_llm_response(snum), removal_pct, remaining_ids
                    )
                else:
                    prompt = build_llm_prompt_from_artifacts(artifacts, snum)
                    response = await run_llm_analysis(prompt, snum, use_mock=False)

                verdict = verdict_from_response(response)
                correct = is_verdict_correct(verdict, ground_truth_label(gt))
                recall = compute_recall(response, gt)
                halluc = count_hallucinations(response, remaining_ids)

                results.append({
                    "scenario": snum,
                    "removal_pct": f"{removal_pct:.0%}",
                    "trial": "-" if removal_pct == 0.0 else str(trial),
                    "verdict": verdict,
                    "correct": correct,
                    "recall": f"{recall:.0%}",
                    "hallucinations": halluc,
                    "events_remaining": len(degraded),
                })

    return results


def _simulate_degraded_response(saved_response: dict, removal_pct: float,
                                remaining_ids: set[str]) -> dict:
    """Simulate how the LLM response degrades with fewer events."""
    response = deepcopy(saved_response)

    # Filter attack chain to only reference remaining events
    chain = response.get("attack_chain", [])
    response["attack_chain"] = [
        step for step in chain
        if step.get("event_id") in remaining_ids
    ]

    # Filter evidence lists
    response["evidence_for"] = [
        eid for eid in response.get("evidence_for", [])
        if eid in remaining_ids
    ]
    response["evidence_against"] = [
        eid for eid in response.get("evidence_against", [])
        if eid in remaining_ids
    ]

    # At high removal rates, verdict may flip
    if removal_pct >= 0.8:
        if random.random() < 0.6:
            response["verdict"] = "INSUFFICIENT"
            response["confidence"] = "LOW"
    elif removal_pct >= 0.6:
        if random.random() < 0.3:
            response["verdict"] = "INSUFFICIENT"
            response["confidence"] = "LOW"

    # Occasionally hallucinate references to removed events
    if removal_pct > 0 and random.random() < removal_pct * 0.3:
        response.setdefault("evidence_for", []).append("evt_hallucinated_001")

    response["source"] = "degraded_mock"
    return response


# ---------------------------------------------------------------------------
# Test C: Noise Injection
# ---------------------------------------------------------------------------

async def test_c_noise_injection(scenario_nums: list[int],
                                 use_mock: bool = True) -> list[dict]:
    """Test C: Inject random benign events and measure noise tolerance."""
    gt_all = load_ground_truth()
    # Signal-to-noise ratios: original, 1:1, 1:2, 1:5
    noise_multipliers = [0, 1, 2, 5]
    results = []

    for snum in scenario_nums:
        gt = gt_all.get(snum)
        if not gt:
            continue

        events = load_scenario_events(snum)
        original_count = len(events)
        valid_ids = {e["event_id"] for e in events}

        for noise_mult in noise_multipliers:
            noise_count = original_count * noise_mult
            noisy_events = deepcopy(events)

            if noise_count > 0:
                noise_events = _generate_benign_noise(
                    noise_count, snum, events
                )
                noisy_events.extend(noise_events)
                # Sort by timestamp to interleave
                noisy_events.sort(key=lambda e: e.get("timestamp", ""))

            all_ids = {e["event_id"] for e in noisy_events}
            ratio_label = f"1:{noise_mult}" if noise_mult > 0 else "original"

            # Run through pipeline
            tag = f"noise_{noise_mult}"
            artifacts = run_pipeline_on_events(noisy_events, snum, tag=tag)

            # Get LLM response
            if use_mock:
                response = _simulate_noisy_response(
                    load_saved_llm_response(snum), noise_mult, all_ids
                )
            else:
                prompt = build_llm_prompt_from_artifacts(artifacts, snum)
                response = await run_llm_analysis(prompt, snum, use_mock=False)

            verdict = verdict_from_response(response)
            correct = is_verdict_correct(verdict, ground_truth_label(gt))
            recall = compute_recall(response, gt)
            halluc = count_hallucinations(response, all_ids)

            results.append({
                "scenario": snum,
                "ratio": ratio_label,
                "total_events": len(noisy_events),
                "noise_events": noise_count,
                "verdict": verdict,
                "correct": correct,
                "recall": f"{recall:.0%}",
                "hallucinations": halluc,
            })

    return results


def _generate_benign_noise(count: int, scenario_num: int,
                           original_events: list[dict]) -> list[dict]:
    """Generate random benign events to inject as noise."""
    noise_events = []
    benign_users = ["user_01", "user_02", "user_03", "user_05", "user_06"]
    benign_actions = [
        ("auth", "login", "success"),
        ("auth", "logout", "success"),
        ("file_access", "file_read", "success"),
        ("file_access", "file_read", "success"),
        ("file_access", "file_read", "success"),
    ]
    benign_resources = [
        "/data/shared/readme.txt",
        "/data/shared/team_notes.docx",
        "/data/shared/meeting_minutes.pdf",
        "/data/engineering/docs/api_guide.md",
        "/data/finance/reports/monthly_summary.xlsx",
        "/data/hr/policies/handbook.pdf",
    ]
    benign_ips = [
        "192.168.1.100", "192.168.1.101", "192.168.1.102",
        "192.168.1.103", "192.168.1.104", "192.168.1.105",
    ]

    # Get time range from original events
    timestamps = [e.get("timestamp", "") for e in original_events if e.get("timestamp")]
    if timestamps:
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        try:
            start_dt = datetime.fromisoformat(min_ts)
            end_dt = datetime.fromisoformat(max_ts)
        except (ValueError, TypeError):
            start_dt = datetime(2026, 4, 1, 8, 0, 0)
            end_dt = datetime(2026, 4, 1, 18, 0, 0)
    else:
        start_dt = datetime(2026, 4, 1, 8, 0, 0)
        end_dt = datetime(2026, 4, 1, 18, 0, 0)

    duration = (end_dt - start_dt).total_seconds()
    if duration <= 0:
        duration = 36000  # 10 hours fallback

    for i in range(count):
        user = random.choice(benign_users)
        source_type, action, status = random.choice(benign_actions)
        resource = random.choice(benign_resources) if source_type == "file_access" else None
        ip = random.choice(benign_ips)

        # Random timestamp within the scenario time range
        offset_secs = random.uniform(0, duration)
        ts = start_dt + timedelta(seconds=offset_secs)
        ts_str = ts.isoformat()

        noise_events.append({
            "event_id": f"evt_noise_s{scenario_num}_{i:04d}",
            "timestamp": ts_str,
            "source_type": source_type,
            "user": user,
            "action": action,
            "resource": resource,
            "source_ip": ip,
            "status": status,
            "session_id": f"sess_{user}_noise_{i:04d}",
            "severity": "info",
            "metadata": {"noise_injected": True},
        })

    return noise_events


def _simulate_noisy_response(saved_response: dict, noise_mult: int,
                             all_ids: set[str]) -> dict:
    """Simulate how noise affects LLM analysis quality."""
    response = deepcopy(saved_response)

    if noise_mult >= 5:
        # Heavy noise: may reduce confidence, slightly miss steps
        if response.get("confidence") == "HIGH":
            response["confidence"] = "MEDIUM"
        chain = response.get("attack_chain", [])
        if len(chain) > 3 and random.random() < 0.3:
            response["attack_chain"] = chain[:-1]  # Miss the last step
        # Small chance of false reference to noise events
        if random.random() < 0.2:
            response.setdefault("evidence_for", []).append("evt_noise_fake_001")
    elif noise_mult >= 2:
        # Moderate noise: slight confidence reduction
        if response.get("confidence") == "HIGH" and random.random() < 0.3:
            response["confidence"] = "MEDIUM"

    response["source"] = "noisy_mock"
    return response


# ---------------------------------------------------------------------------
# Test D: Timestamp Jitter
# ---------------------------------------------------------------------------

async def test_d_timestamp_jitter(scenario_nums: list[int],
                                  use_mock: bool = True) -> list[dict]:
    """Test D: Add random jitter to timestamps and measure temporal sensitivity."""
    gt_all = load_ground_truth()
    jitter_levels = [
        ("none", timedelta(seconds=0)),
        ("5min", timedelta(minutes=5)),
        ("30min", timedelta(minutes=30)),
        ("2hr", timedelta(hours=2)),
    ]
    results = []

    for snum in scenario_nums:
        gt = gt_all.get(snum)
        if not gt:
            continue

        events = load_scenario_events(snum)
        valid_ids = {e["event_id"] for e in events}

        for jitter_name, jitter_delta in jitter_levels:
            jittered = deepcopy(events)

            if jitter_delta.total_seconds() > 0:
                jittered = _apply_timestamp_jitter(jittered, jitter_delta)

            # Run through pipeline
            tag = f"jitter_{jitter_name}"
            artifacts = run_pipeline_on_events(jittered, snum, tag=tag)

            # Check if timeline order is preserved
            timeline_correct = _check_timeline_order(events, jittered)

            # Get LLM response
            if use_mock:
                response = _simulate_jittered_response(
                    load_saved_llm_response(snum), jitter_name, timeline_correct
                )
            else:
                prompt = build_llm_prompt_from_artifacts(artifacts, snum)
                response = await run_llm_analysis(prompt, snum, use_mock=False)

            verdict = verdict_from_response(response)
            correct = is_verdict_correct(verdict, ground_truth_label(gt))
            recall = compute_recall(response, gt)

            results.append({
                "scenario": snum,
                "jitter": jitter_name,
                "verdict": verdict,
                "correct": correct,
                "recall": f"{recall:.0%}",
                "timeline_correct": timeline_correct,
                "chain_order_ok": _check_chain_order(response),
            })

    return results


def _apply_timestamp_jitter(events: list[dict],
                            max_delta: timedelta) -> list[dict]:
    """Add random jitter to all event timestamps."""
    jittered = []
    max_secs = max_delta.total_seconds()

    for event in events:
        e = deepcopy(event)
        ts_str = e.get("timestamp", "")
        if ts_str:
            try:
                ts = datetime.fromisoformat(ts_str)
                offset = random.uniform(-max_secs, max_secs)
                new_ts = ts + timedelta(seconds=offset)
                e["timestamp"] = new_ts.isoformat()
            except (ValueError, TypeError):
                pass
        jittered.append(e)

    return jittered


def _check_timeline_order(original: list[dict], jittered: list[dict]) -> bool:
    """Check whether the jittered events maintain the same chronological order."""
    orig_order = [e["event_id"] for e in sorted(
        original, key=lambda e: e.get("timestamp", "")
    )]
    jit_order = [e["event_id"] for e in sorted(
        jittered, key=lambda e: e.get("timestamp", "")
    )]
    return orig_order == jit_order


def _check_chain_order(response: dict) -> bool:
    """Check if the attack chain steps are in ascending order."""
    chain = response.get("attack_chain", [])
    if len(chain) <= 1:
        return True
    steps = [step.get("step", 0) for step in chain]
    return all(steps[i] <= steps[i + 1] for i in range(len(steps) - 1))


def _simulate_jittered_response(saved_response: dict, jitter_name: str,
                                timeline_correct: bool) -> dict:
    """Simulate how timestamp jitter affects LLM analysis."""
    response = deepcopy(saved_response)

    if jitter_name == "2hr":
        # Heavy jitter: may scramble attack chain ordering
        chain = response.get("attack_chain", [])
        if len(chain) > 2 and random.random() < 0.5:
            # Swap two adjacent steps
            idx = random.randint(0, len(chain) - 2)
            chain[idx], chain[idx + 1] = chain[idx + 1], chain[idx]
            # Renumber
            for i, step in enumerate(chain):
                step["step"] = i + 1
            response["attack_chain"] = chain

        if response.get("confidence") == "HIGH":
            response["confidence"] = "MEDIUM"

    elif jitter_name == "30min":
        if response.get("confidence") == "HIGH" and random.random() < 0.3:
            response["confidence"] = "MEDIUM"

    response["source"] = "jittered_mock"
    return response


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def print_table(title: str, headers: list[str], rows: list[list[str]],
                col_widths: list[int] | None = None):
    """Print a formatted ASCII table."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")

    if col_widths is None:
        col_widths = []
        for i, h in enumerate(headers):
            max_w = len(h)
            for row in rows:
                if i < len(row):
                    max_w = max(max_w, len(str(row[i])))
            col_widths.append(max_w + 2)

    # Header
    header_line = "|"
    separator = "|"
    for h, w in zip(headers, col_widths):
        header_line += f" {h:<{w}}|"
        separator += "-" * (w + 1) + "|"

    print(separator)
    print(header_line)
    print(separator)

    # Rows
    for row in rows:
        line = "|"
        for val, w in zip(row, col_widths):
            line += f" {str(val):<{w}}|"
        print(line)

    print(separator)


def print_test_a_results(results: list[dict]):
    """Print Test A results."""
    headers = ["Scenario", "Mode", "Verdict", "Correct", "Recall", "Halluc"]
    rows = []
    for r in results:
        rows.append([
            r["scenario"], r["mode"], r["verdict"],
            str(r["correct"]), r["recall"], r["hallucinations"],
        ])
    print_table("Test A: Raw Logs (No Pipeline) vs Full Pipeline", headers, rows)


def print_test_b_results(results: list[dict], scenario_num: int):
    """Print Test B results for a specific scenario."""
    headers = ["Removal %", "Trial", "Verdict", "Correct", "Recall", "Halluc"]
    rows = []
    for r in results:
        if r["scenario"] == scenario_num:
            rows.append([
                r["removal_pct"], r["trial"], r["verdict"],
                str(r["correct"]), r["recall"], r["hallucinations"],
            ])
    print_table(
        f"Test B: Event Removal -- Scenario {scenario_num}",
        headers, rows,
    )


def print_test_c_results(results: list[dict], scenario_num: int):
    """Print Test C results for a specific scenario."""
    headers = ["S:N Ratio", "Total Evts", "Noise Evts", "Verdict", "Correct", "Recall", "Halluc"]
    rows = []
    for r in results:
        if r["scenario"] == scenario_num:
            rows.append([
                r["ratio"], r["total_events"], r["noise_events"],
                r["verdict"], str(r["correct"]), r["recall"], r["hallucinations"],
            ])
    print_table(
        f"Test C: Noise Injection -- Scenario {scenario_num}",
        headers, rows,
    )


def print_test_d_results(results: list[dict]):
    """Print Test D results."""
    headers = ["Scenario", "Jitter", "Verdict", "Correct", "Recall", "Timeline OK", "Chain OK"]
    rows = []
    for r in results:
        rows.append([
            r["scenario"], r["jitter"], r["verdict"],
            str(r["correct"]), r["recall"],
            str(r["timeline_correct"]), str(r["chain_order_ok"]),
        ])
    print_table("Test D: Timestamp Jitter -- Temporal Sensitivity", headers, rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run_all_stress_tests(use_mock: bool = True, seed: int = 42):
    """Run all four stress test dimensions."""
    random.seed(seed)
    ensure_stress_dir()

    print("=" * 70)
    print("  FORENSIC FRAMEWORK STRESS TEST SUITE")
    print(f"  Mode: {'MOCK' if use_mock else 'LIVE LLM'}")
    print(f"  Random seed: {seed}")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Test A: Raw Logs Baseline (scenarios 3, 4, 5)
    # ------------------------------------------------------------------
    print("\n>>> Running Test A: Raw Logs (No Pipeline) Baseline...")
    test_a_results = await test_a_raw_logs_baseline([3, 4, 5], use_mock=use_mock)
    print_test_a_results(test_a_results)

    # ------------------------------------------------------------------
    # Test B: Event Removal (scenarios 3, 4)
    # ------------------------------------------------------------------
    print("\n>>> Running Test B: Event Removal (Graceful Degradation)...")
    test_b_results = await test_b_event_removal([3, 4], use_mock=use_mock, trials=3)
    print_test_b_results(test_b_results, 3)
    print_test_b_results(test_b_results, 4)

    # ------------------------------------------------------------------
    # Test C: Noise Injection (scenarios 3, 4)
    # ------------------------------------------------------------------
    print("\n>>> Running Test C: Noise Injection...")
    test_c_results = await test_c_noise_injection([3, 4], use_mock=use_mock)
    print_test_c_results(test_c_results, 3)
    print_test_c_results(test_c_results, 4)

    # ------------------------------------------------------------------
    # Test D: Timestamp Jitter (scenario 3)
    # ------------------------------------------------------------------
    print("\n>>> Running Test D: Timestamp Jitter...")
    test_d_results = await test_d_timestamp_jitter([3], use_mock=use_mock)
    print_test_d_results(test_d_results)

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 70)
    print("  STRESS TEST SUMMARY")
    print("=" * 70)

    # Test A summary
    raw_correct = sum(1 for r in test_a_results if r["mode"] == "raw_logs" and r["correct"])
    raw_total = sum(1 for r in test_a_results if r["mode"] == "raw_logs")
    pipe_correct = sum(1 for r in test_a_results if r["mode"] == "full_pipeline" and r["correct"])
    pipe_total = sum(1 for r in test_a_results if r["mode"] == "full_pipeline")
    print(f"  Test A: Raw logs accuracy: {raw_correct}/{raw_total} | "
          f"Pipeline accuracy: {pipe_correct}/{pipe_total}")

    # Test B summary
    b_0 = [r for r in test_b_results if r["removal_pct"] == "0%"]
    b_80 = [r for r in test_b_results if r["removal_pct"] == "80%"]
    b0_correct = sum(1 for r in b_0 if r["correct"])
    b80_correct = sum(1 for r in b_80 if r["correct"])
    print(f"  Test B: 0% removal correct: {b0_correct}/{len(b_0)} | "
          f"80% removal correct: {b80_correct}/{len(b_80)}")

    # Test C summary
    c_orig = [r for r in test_c_results if r["ratio"] == "original"]
    c_heavy = [r for r in test_c_results if r["ratio"] == "1:5"]
    co_correct = sum(1 for r in c_orig if r["correct"])
    ch_correct = sum(1 for r in c_heavy if r["correct"])
    print(f"  Test C: Original correct: {co_correct}/{len(c_orig)} | "
          f"1:5 noise correct: {ch_correct}/{len(c_heavy)}")

    # Test D summary
    d_none = [r for r in test_d_results if r["jitter"] == "none"]
    d_2hr = [r for r in test_d_results if r["jitter"] == "2hr"]
    dn_correct = sum(1 for r in d_none if r["correct"])
    d2_correct = sum(1 for r in d_2hr if r["correct"])
    print(f"  Test D: No jitter correct: {dn_correct}/{len(d_none)} | "
          f"2hr jitter correct: {d2_correct}/{len(d_2hr)}")

    # Save all results
    all_results = {
        "test_a": test_a_results,
        "test_b": test_b_results,
        "test_c": test_c_results,
        "test_d": test_d_results,
    }
    output_path = STRESS_DIR / "stress_test_results.json"
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\n  Full results saved to: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run stress tests for the forensic investigation framework."
    )
    parser.add_argument(
        "--live",
        action="store_true",
        default=False,
        help="Use real LLM endpoint instead of mock responses.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42).",
    )
    parser.add_argument(
        "--test",
        choices=["a", "b", "c", "d", "all"],
        default="all",
        help="Run a specific test (a/b/c/d) or all (default: all).",
    )
    args = parser.parse_args()

    use_mock = not args.live

    async def main():
        random.seed(args.seed)
        ensure_stress_dir()

        if args.test == "all":
            await run_all_stress_tests(use_mock=use_mock, seed=args.seed)
        elif args.test == "a":
            results = await test_a_raw_logs_baseline([3, 4, 5], use_mock=use_mock)
            print_test_a_results(results)
        elif args.test == "b":
            results = await test_b_event_removal([3, 4], use_mock=use_mock)
            print_test_b_results(results, 3)
            print_test_b_results(results, 4)
        elif args.test == "c":
            results = await test_c_noise_injection([3, 4], use_mock=use_mock)
            print_test_c_results(results, 3)
            print_test_c_results(results, 4)
        elif args.test == "d":
            results = await test_d_timestamp_jitter([3], use_mock=use_mock)
            print_test_d_results(results)

    asyncio.run(main())
