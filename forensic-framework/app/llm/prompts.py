"""LLM prompt builder for forensic analysis scenarios."""

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

LLM_SYSTEM_PROMPT = (
    "You are a digital forensic analyst investigating a private cloud environment "
    "after a suspected security incident. Analyze the structured evidence below.\n"
    "\n"
    "STRICT RULES:\n"
    "1. Only reason about events explicitly listed in the CORRELATED TIMELINE.\n"
    "2. Do NOT assume, invent, or infer events not present.\n"
    "3. If evidence is insufficient, say \"INSUFFICIENT EVIDENCE.\"\n"
    "4. Reference specific event_ids for every claim.\n"
    "5. Assign confidence: HIGH, MEDIUM, or LOW to each claim.\n"
    "\n"
    "CRITICAL ANALYSIS GUIDANCE:\n"
    "6. Distinguish between SUCCESSFUL attacks (data was accessed/exfiltrated) and "
    "FAILED attack attempts (all login attempts failed, no data was accessed).\n"
    "7. Failed login attempts alone, without a subsequent successful login, do NOT "
    "constitute a security incident — they indicate an attempted but unsuccessful attack.\n"
    "8. Legitimate maintenance activity by authorized users may involve privilege changes, "
    "log rotation/deletion, off-hours access, and bulk file operations. Check the user's "
    "role, baseline, and whether actions are consistent with maintenance tasks before "
    "flagging as malicious.\n"
    "9. Consider whether metadata includes legitimate justification (ticket numbers, "
    "maintenance windows).\n"
    "10. A high volume of alerts does NOT automatically mean an attack occurred — evaluate "
    "the CONTEXT of each alert.\n"
    "11. Be especially vigilant for INSIDER THREATS: authorized users who gradually expand "
    "access scope across departments over multiple days, transition from reading to downloading, "
    "or access sensitive files outside their department. A plausible justification does not "
    "rule out malicious intent — evaluate the PATTERN of behavior, not just individual events.\n"
    "12. Mid-session IP changes (same session_id, different source_ip) are strong indicators "
    "of session hijacking and should be treated as suspicious."
)


def build_analysis_prompt(
    baselines: dict,
    timeline: list,
    triggered_rules: list,
    scenario_id: str,
) -> str:
    """Build the full analysis prompt from structured forensic data.

    Args:
        baselines: User baseline profiles.
        timeline: Ordered list of correlated timeline events.
        triggered_rules: List of rule alert dicts that fired for the scenario.
        scenario_id: Identifier string for the scenario (e.g. "scenario_3").

    Returns:
        The formatted prompt string requesting structured JSON analysis.
    """
    user_baselines_json = json.dumps(baselines, indent=2)
    timeline_json = json.dumps(timeline, indent=2)
    triggered_rules_json = json.dumps(triggered_rules, indent=2)

    prompt = f"""Analyze Scenario: {scenario_id}

USER BASELINES:
{user_baselines_json}

CORRELATED TIMELINE:
{timeline_json}

TRIGGERED RULES:
{triggered_rules_json}

IMPORTANT CONTEXT FOR ANALYSIS:
- Failed login attempts without subsequent successful login = attempted attack, NOT a breach. Verdict should be NO.
- Authorized users performing MAINTENANCE may legitimately: change privileges, delete old logs, download backups, work off-hours from VPN IPs. Look for: (a) privileges reverted after work, (b) files accessed are config/backup type, not sensitive data.
- HOWEVER, be skeptical of insider threats: if a user accesses files OUTSIDE their normal department (e.g., HR person reading finance files, or accessing engineering data), this is suspicious even if they have a ticket justification. Tickets can be fabricated.
- A pattern of read-then-download across multiple days, especially across departments, suggests premeditated data collection — this IS an incident even if each individual day looks benign.
- If a user's IP changes MID-SESSION (same session_id, different source_ip), this strongly suggests session hijacking — the original user did not change locations during a single session.
- The verdict should reflect whether UNAUTHORIZED ACCESS or DATA EXFILTRATION occurred, not just whether alerts fired.

ANALYSIS TASKS:
1. VERDICT: Is there evidence of a security incident? (YES / NO / INSUFFICIENT)
2. ATTACK CHAIN: If YES, list ordered steps. Each step must cite an event_id.
3. SUSPECT: Most suspicious user. Explain using only the evidence.
4. SUPPORTING EVIDENCE: List event_ids that support your verdict.
5. COUNTER-EVIDENCE: List event_ids that weaken your verdict.
6. GAPS: What evidence is missing that would strengthen the analysis?
7. CONFIDENCE: Overall confidence with explanation.

Respond in JSON:
{{
  "verdict": "YES | NO | INSUFFICIENT",
  "incident_occurred": "true | false  // Did an actual breach/unauthorized access happen?",
  "confidence": "HIGH | MEDIUM | LOW",
  "confidence_explanation": "...",
  "suspect": "user_id or null",
  "attack_chain": [
    {{"step": 1, "event_id": "evt_xxx", "description": "...", "confidence": "HIGH|MEDIUM|LOW"}}
  ],
  "evidence_for": ["evt_xxx"],
  "evidence_against": ["evt_zzz"],
  "gaps": ["..."],
  "narrative": "2-3 sentence summary"
}}"""
    return prompt


def build_scenario_prompt(scenario_num: int) -> str:
    """Load all data files for a scenario and build the full analysis prompt.

    Args:
        scenario_num: The scenario number (1-4).

    Returns:
        The complete prompt string ready to send to an LLM.
    """
    data_dir = PROJECT_ROOT / "data"
    normalized_dir = data_dir / "normalized"

    # Load user baselines
    baselines_path = data_dir / "user_baselines.json"
    with open(baselines_path, "r") as f:
        baselines = json.load(f)

    # Load timeline
    timeline_path = normalized_dir / f"scenario_{scenario_num}_timeline.json"
    with open(timeline_path, "r") as f:
        timeline_data = json.load(f)
    timeline = timeline_data.get("timeline", [])

    # Load rule results
    rules_path = normalized_dir / f"scenario_{scenario_num}_rule_results.json"
    with open(rules_path, "r") as f:
        rules_data = json.load(f)
    triggered_rules = rules_data.get("alerts", [])

    scenario_id = f"scenario_{scenario_num}"
    return build_analysis_prompt(baselines, timeline, triggered_rules, scenario_id)
