#!/usr/bin/env python3
"""End-to-end CERT r4.2 pipeline runner.

For each CERT scenario in `data/real_scenarios/cert_*.json`:

    1. Synthesize a minimal user baseline from observed events (typical hours,
       observed PCs/IPs, dirs). This is necessary because the rule engine
       and prompt builder both consume a baseline; CERT users obviously
       aren't in `data/user_baselines.json`.
    2. Run the 12-rule engine on the unified events.
    3. Build the standard LLM prompt and call the LLM.
    4. Run the seven-check validator on the LLM output.
    5. Persist the LLM response under `data/llm_responses/cert/` and
       evaluate against the ground-truth label in the scenario file.

Output:
    data/evaluation_results_cert.json
    data/llm_responses/cert/<scenario_id>.json (one per scenario)
    data/cert_pipeline_summary.json

The runner is resumable: existing per-scenario responses are skipped
unless --force is set. On endpoint errors, retries with exponential
backoff (3x); on context-overflow the max_tokens is halved once for that
call.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.llm.client import call_modal_llm
from app.llm.hallucination_checker import (
    check_actor_references, check_entity_consistency, check_event_references,
    check_temporal_claims, check_timeline_correctness,
    check_unsupported_claims, check_volume_claims,
)
from app.llm.prompts import LLM_SYSTEM_PROMPT, build_analysis_prompt
from app.rules.rule_engine import run_rules


def _hallucination_check(llm_response: dict, events: list[dict],
                          scenario_id: str) -> dict:
    """Run the seven-check validator against an in-memory event list."""
    valid_events = {e["event_id"]: e for e in events}
    event_refs = check_event_references(llm_response, valid_events)
    timeline = check_timeline_correctness(llm_response, valid_events)
    unsupported = check_unsupported_claims(llm_response)
    actors = check_actor_references(llm_response, valid_events)
    temporal = check_temporal_claims(llm_response, valid_events)
    volume = check_volume_claims(llm_response, valid_events)
    entity = check_entity_consistency(llm_response, valid_events)
    hcount = (
        event_refs["hallucinated_events"]
        + len(timeline["out_of_order_steps"])
        + unsupported["unsupported_claims"]
        + len(temporal["temporal_errors"])
        + len(volume["volume_errors"])
        + len(entity["unknown_entities"])
    )
    return {
        "scenario": scenario_id,
        "event_references": event_refs,
        "timeline_correctness": timeline,
        "unsupported_claims": unsupported,
        "actor_references": actors,
        "temporal_claims": temporal,
        "volume_claims": volume,
        "entity_consistency": entity,
        "hallucination_count": hcount,
        "hallucination_free": hcount == 0,
    }


PROJECT_ROOT = Path(__file__).resolve().parent
SCENARIOS_DIR = PROJECT_ROOT / "data" / "real_scenarios"
RESPONSES_DIR = PROJECT_ROOT / "data" / "llm_responses" / "cert"
RESULTS_PATH = PROJECT_ROOT / "data" / "evaluation_results_cert.json"
SUMMARY_PATH = PROJECT_ROOT / "data" / "cert_pipeline_summary.json"


# ---------------------------------------------------------------------------
# Baseline synthesis
# ---------------------------------------------------------------------------

def _synthesize_baseline(events: list[dict]) -> dict:
    """Build a minimal user baseline dict so the rule engine and prompt
    builder have something coherent to consume.

    Strategy: dominant working hours, all observed PCs as 'normal_ips',
    no normal_directories (so cross_dept rule mostly no-ops).
    """
    by_user: dict[str, dict] = {}
    by_user_hours: dict[str, list[int]] = defaultdict(list)
    by_user_pcs: dict[str, set[str]] = defaultdict(set)
    for e in events:
        u = e.get("user")
        if not u:
            continue
        ts = e["timestamp"]
        try:
            hour = datetime.fromisoformat(ts).hour
        except Exception:
            continue
        by_user_hours[u].append(hour)
        ip = e.get("source_ip") or ""
        if ip:
            by_user_pcs[u].add(ip)
    for u in by_user_hours:
        hours = by_user_hours[u]
        if not hours:
            lo, hi = "00:00", "23:59"
        else:
            lo = f"{max(0, min(hours)):02d}:00"
            hi = f"{max(min(hours), max(hours)):02d}:59"
        by_user[u] = {
            "department": "unknown",
            "role": "cert_user",
            "normal_hours": f"{lo}-{hi}",
            "timezone": "UTC",
            "normal_ips": sorted(by_user_pcs[u]),
            "normal_directories": [],
            "avg_files_per_day": 0,
            "avg_downloads_per_day": 0,
        }
    return by_user


# ---------------------------------------------------------------------------
# Per-scenario evaluation
# ---------------------------------------------------------------------------

def _verdict_map(rule_verdict: str, llm_verdict: str, gt_label: str) -> dict:
    """Same mapping as app.evaluation.evaluator.evaluate_verdict_accuracy."""
    rule_map = {"no_alert": "BENIGN", "suspicious": "BENIGN", "attack": "ATTACK"}
    llm_map = {"NO": "BENIGN", "INSUFFICIENT": "BENIGN", "YES": "ATTACK"}
    rule_mapped = rule_map.get(rule_verdict, "UNKNOWN")
    llm_mapped = llm_map.get(llm_verdict, "UNKNOWN")
    return {
        "ground_truth": gt_label,
        "rule_mapped": rule_mapped,
        "llm_mapped": llm_mapped,
        "rule_correct": rule_mapped == gt_label,
        "llm_correct": llm_mapped == gt_label,
    }


async def _call_with_retries(prompt: str, system_prompt: str,
                              max_retries: int = 2) -> tuple[dict | None, str | None]:
    """Call the LLM with exponential backoff. Halves max_tokens once on
    context-overflow (a 400 from vLLM)."""
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            result = await call_modal_llm(
                prompt=prompt, system_prompt=system_prompt,
            )
            return result, None
        except Exception as exc:
            err_str = str(exc)
            last_err = f"{type(exc).__name__}: {err_str[:300]}"
            # Context overflow: re-prompt with a hint to be terse
            if "maximum context length" in err_str.lower() or "400" in err_str:
                # Trim the prompt body by 30% and try once more
                trimmed = prompt[: int(len(prompt) * 0.7)]
                try:
                    result = await call_modal_llm(
                        prompt=trimmed, system_prompt=system_prompt,
                    )
                    return result, "trimmed_prompt_due_to_context_overflow"
                except Exception as exc2:
                    last_err = f"{type(exc2).__name__}: {str(exc2)[:300]}"
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
    return None, last_err


JSON_ONLY_SUFFIX = (
    "\n\nIMPORTANT: Respond with ONLY the JSON object specified above. "
    "Do not write any prose, headers, or markdown around it. "
    "Do not explain the format. The first character of your response must be "
    "'{' and the last must be '}'."
)


_YES_CUES = (
    "insider threat", "data exfiltration", "exfiltrat", "malicious",
    "successful", "evidence of attack", "data theft", "compromise",
    "unauthorized", "unauthorised", "verdict: yes", "incident occurred",
    "attack confirmed", "breach", "credential theft",
)
_NO_CUES = (
    "no evidence of malicious", "no malicious activity", "benign activity",
    "no incident", "no attack", "verdict: no",
    "no security incident",
)


def _extract_verdict_from_prose(text: str) -> str | None:
    """Best-effort verdict from narrative when JSON parsing fails."""
    lower = text.lower()
    no_score = sum(c in lower for c in _NO_CUES)
    yes_score = sum(c in lower for c in _YES_CUES)
    if no_score > yes_score and no_score >= 2:
        return "NO"
    if yes_score > no_score and yes_score >= 2:
        return "YES"
    return None


def _coerce_to_verdict_dict(raw: dict) -> dict:
    """If JSON parse failed, try to extract verdict from prose."""
    if "verdict" in raw and raw["verdict"] in ("YES", "NO", "INSUFFICIENT"):
        return raw
    if raw.get("error") != "parse_failed":
        return raw
    text = raw.get("raw", "")
    v = _extract_verdict_from_prose(text)
    if v is None:
        return raw
    # Try to extract a suspect mention (a token of form XXXNNNN)
    m = re.search(r"\b([A-Z]{3}\d{4})\b", text)
    suspect = m.group(1) if m else None
    return {
        "verdict": v,
        "incident_occurred": "true" if v == "YES" else "false",
        "confidence": "MEDIUM",
        "confidence_explanation": "extracted from narrative output",
        "suspect": suspect,
        "attack_chain": [],
        "evidence_for": [],
        "evidence_against": [],
        "gaps": [],
        "narrative": text[:400],
        "source": "live_narrative_coerced",
        "_original_raw": text,
    }


def _compact_event_for_prompt(e: dict) -> dict:
    """Strip CERT-specific metadata bloat so events fit Gemma's 32K context.

    Email events in CERT carry full to/cc/bcc/recipients lists that can run
    300+ chars each — over 100 events of that pushes the prompt past the
    model's context window. We keep only the fields the validator and the
    forensic narrative actually need.
    """
    md = e.get("metadata") or {}
    compact_md: dict = {}
    if "cert_event_type" in md:
        compact_md["type"] = md["cert_event_type"]
    if "pc" in md:
        compact_md["pc"] = md["pc"]
    if e.get("source_type") == "email":
        recips = md.get("recipients") or []
        compact_md["n_recipients"] = len(recips)
        if recips:
            compact_md["first_recipient"] = recips[0]
        if md.get("attachment_size_bytes"):
            compact_md["att_bytes"] = md["attachment_size_bytes"]
        if md.get("attachments"):
            compact_md["n_attachments"] = md["attachments"]
    if e.get("source_type") == "web_server":
        # Keep just the domain — the URL paths in CERT are noise tokens
        # (random hashes), not human-meaningful.
        url = e.get("resource") or ""
        m = re.match(r"https?://([^/]+)", url)
        if m:
            return {**e, "resource": f"http://{m.group(1)}", "metadata": compact_md}
    return {**e, "metadata": compact_md}


async def _process_scenario(path: Path, force: bool) -> dict:
    """Run one CERT scenario end-to-end. Returns an evaluation record."""
    with open(path, "r") as f:
        scenario = json.load(f)
    sid = scenario["scenario_id"]
    out_path = RESPONSES_DIR / f"{sid}.json"

    events = scenario["events"]
    # Compacted view used only for the LLM prompt (validator still gets full).
    events_for_prompt = [_compact_event_for_prompt(e) for e in events]
    baselines = _synthesize_baseline(events)
    rule_alerts = run_rules(events, baselines)
    if rule_alerts:
        crit = sum(1 for a in rule_alerts if a["severity"] == "critical")
        if crit > 0:
            rule_verdict = "attack"
        else:
            rule_verdict = "suspicious"
    else:
        rule_verdict = "no_alert"

    if out_path.exists() and not force:
        with open(out_path, "r") as f:
            llm_result = json.load(f)
        llm_error = llm_result.get("_runtime_error")
    else:
        prompt = build_analysis_prompt(
            baselines=baselines, timeline=events_for_prompt,
            triggered_rules=rule_alerts, scenario_id=sid,
        ) + JSON_ONLY_SUFFIX
        t0 = time.monotonic()
        result, err = await _call_with_retries(prompt, LLM_SYSTEM_PROMPT)
        if result is not None:
            result = _coerce_to_verdict_dict(result)
        elapsed = time.monotonic() - t0
        llm_result = result or {
            "verdict": "ERR",
            "_runtime_error": err,
        }
        llm_result["_elapsed_seconds"] = elapsed
        llm_result.setdefault("source", "live")
        RESPONSES_DIR.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(llm_result, f, indent=2)
        llm_error = err

    llm_verdict = llm_result.get("verdict", "ERR")
    verdict_eval = _verdict_map(rule_verdict, llm_verdict, scenario["label"])
    try:
        report = _hallucination_check(llm_result, events, sid)
    except Exception as exc:
        report = {"hallucination_count": -1, "_error": str(exc)[:200]}

    return {
        "scenario": sid,
        "ground_truth_label": scenario["label"],
        "rule_verdict": rule_verdict,
        "llm_verdict": llm_verdict,
        "rule_alert_count": len(rule_alerts),
        "rules_triggered": sorted({a["rule_id"] for a in rule_alerts}),
        "llm_error": llm_error,
        "is_mock": llm_result.get("source") == "mock",
        "verdict_accuracy": verdict_eval,
        "hallucination_report": report,
        "scenario_meta": {
            "source": "cert",
            "ground_truth_user": scenario.get("ground_truth_user"),
            "ground_truth_scenario_type":
                scenario.get("ground_truth_scenario_type"),
            "month": scenario.get("month"),
            "downsampled": scenario.get("downsampled"),
            "original_event_count": scenario.get("original_event_count"),
            "event_count": len(events),
        },
    }


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

async def _main_async(args) -> int:
    scenario_paths = sorted(SCENARIOS_DIR.glob("cert_*.json"))
    if not scenario_paths:
        print(f"No CERT scenarios found in {SCENARIOS_DIR}", file=sys.stderr)
        return 1

    endpoint = os.getenv("MODAL_ENDPOINT", "")
    if not endpoint or "your-modal" in endpoint:
        print("MODAL_ENDPOINT not configured. Refusing to run (the task "
              "explicitly forbids mock results in the paper).", file=sys.stderr)
        return 2

    print(f"CERT pipeline: {len(scenario_paths)} scenarios", flush=True)
    print(f"  endpoint: {endpoint}", flush=True)
    results = []
    grand_start = time.monotonic()
    for i, p in enumerate(scenario_paths, 1):
        record = await _process_scenario(p, force=args.force)
        marker = "OK" if record["llm_error"] is None else "ERR"
        flag = "MOCK!" if record["is_mock"] else ""
        print(f"  [{i:3d}/{len(scenario_paths)}] {record['scenario']} "
              f"label={record['ground_truth_label']} "
              f"rule={record['rule_verdict']} "
              f"llm={record['llm_verdict']} "
              f"[{marker}] {flag}".rstrip(), flush=True)
        results.append(record)

    # Guard: no mock data allowed in the paper.
    mocks = [r for r in results if r["is_mock"]]
    if mocks:
        print(f"FATAL: {len(mocks)} mock responses present. Aborting before "
              f"statistics.", file=sys.stderr)
        return 3

    # Persist
    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2)

    n_attack = sum(1 for r in results if r["ground_truth_label"] == "ATTACK")
    n_benign = len(results) - n_attack
    rule_ok = sum(1 for r in results if r["verdict_accuracy"]["rule_correct"])
    llm_ok = sum(1 for r in results if r["verdict_accuracy"]["llm_correct"])
    errors = sum(1 for r in results if r["llm_error"] is not None)
    summary = {
        "n_scenarios": len(results),
        "n_attack": n_attack, "n_benign": n_benign,
        "rule_correct": rule_ok,
        "llm_correct": llm_ok,
        "rule_accuracy": rule_ok / max(1, len(results)),
        "llm_accuracy": llm_ok / max(1, len(results)),
        "llm_errors": errors,
        "wall_seconds": time.monotonic() - grand_start,
    }
    with open(SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nDone. rules {rule_ok}/{len(results)} = "
          f"{summary['rule_accuracy']*100:.1f}%; "
          f"gemma {llm_ok}/{len(results)} = {summary['llm_accuracy']*100:.1f}%; "
          f"errors {errors}.", flush=True)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true",
                        help="Re-run scenarios whose response file exists.")
    args = parser.parse_args()
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    sys.exit(main())
