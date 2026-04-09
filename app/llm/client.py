"""LLM inference wrapper with Modal client and mock fallback."""

import asyncio
import json
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger("forensic.llm")

import httpx
from dotenv import load_dotenv

from app.llm.prompts import LLM_SYSTEM_PROMPT, build_scenario_prompt

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
load_dotenv(PROJECT_ROOT / ".env")


# ---------------------------------------------------------------------------
# Modal LLM client
# ---------------------------------------------------------------------------

async def call_modal_llm(prompt: str, system_prompt: str = "") -> dict:
    """Call the Modal-hosted LLM endpoint.

    Posts a chat-completions request to the Modal endpoint configured via
    environment variables MODAL_ENDPOINT and MODAL_TOKEN.

    Args:
        prompt: The user prompt to send.
        system_prompt: Optional system prompt (defaults to empty string).

    Returns:
        Parsed JSON dict from the LLM response content.
    """
    endpoint = os.getenv("MODAL_ENDPOINT", "")
    token = os.getenv("MODAL_TOKEN", "")

    url = f"{endpoint}/v1/chat/completions"

    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": os.getenv("MODAL_MODEL", "fusion-brain"),
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 8192,
        "chat_template_kwargs": {"enable_thinking": False},
    }

    headers = {
        "Content-Type": "application/json",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
        response = await client.post(url, json=payload, headers=headers)
        response.raise_for_status()
        data = response.json()

    # Extract content from the OpenAI-compatible response format
    content = data["choices"][0]["message"]["content"]
    return parse_llm_response(content)


# ---------------------------------------------------------------------------
# Mock LLM responses
# ---------------------------------------------------------------------------

def _mock_scenario_1() -> dict:
    """Normal activity -- no incident."""
    return {
        "source": "MOCK",
        "verdict": "NO",
        "confidence": "HIGH",
        "confidence_explanation": (
            "All events for user_01 fall within normal working hours (09:15-17:30), "
            "originate from the expected IP 192.168.1.100, and access only files within "
            "the authorized /data/finance/ directory. File access volume (3 reads) is "
            "below the user's average of 4 files/day. No privilege changes, no downloads, "
            "no failed logins."
        ),
        "suspect": None,
        "attack_chain": [],
        "evidence_for": [],
        "evidence_against": [
            "evt_s1_001",
            "evt_s1_002",
            "evt_s1_003",
            "evt_s1_004",
            "evt_s1_005",
        ],
        "gaps": [
            "Only a single day of activity is available; longer observation would increase confidence.",
            "No network-level telemetry (DNS, NetFlow) to corroborate file access patterns.",
        ],
        "narrative": (
            "user_01 conducted routine financial document reviews during standard business "
            "hours from their usual workstation IP. All accessed resources fall within their "
            "authorized department directory and no rule alerts were triggered. There is no "
            "evidence of a security incident."
        ),
    }


def _mock_scenario_2() -> dict:
    """Travel context -- suspicious at first glance but benign."""
    return {
        "source": "MOCK",
        "verdict": "NO",
        "confidence": "MEDIUM",
        "confidence_explanation": (
            "user_02 logged in from an unusual IP (103.28.45.67) and had an off-hours "
            "evening session, both of which triggered rule alerts. However, the user's "
            "baseline includes a travel_note indicating frequent international travel with "
            "varying IPs. All accessed files are within authorized directories "
            "(/data/engineering/, /data/shared/project_alpha/, /data/shared/project_beta/). "
            "Download volume (5 files, ~21 MB total) is elevated but not extreme for a "
            "senior developer catching up after travel. Confidence is MEDIUM rather than "
            "HIGH because the IP anomaly cannot be fully resolved without travel records."
        ),
        "suspect": None,
        "attack_chain": [],
        "evidence_for": [],
        "evidence_against": [
            "evt_s2_001",
            "evt_s2_002",
            "evt_s2_003",
            "evt_s2_007",
            "evt_s2_009",
            "evt_s2_010",
            "evt_s2_013",
            "evt_s2_015",
            "evt_s2_016",
        ],
        "gaps": [
            "Travel itinerary or VPN logs would confirm whether 103.28.45.67 matches a known travel location.",
            "No MFA logs available to confirm user identity during the off-hours session.",
            "The evening session (21:30-23:25) could indicate a compromised account operating in a different timezone; travel records would disambiguate.",
        ],
        "narrative": (
            "user_02 accessed engineering and shared project files from a non-standard IP "
            "across two sessions including a late-evening session. While rule alerts fired "
            "for unusual IP and off-hours access, the user's baseline documents frequent "
            "travel with variable IPs, and all resources accessed are within authorized "
            "directories. Without travel records to confirm, confidence is MEDIUM that this "
            "is normal activity."
        ),
    }


def _mock_scenario_3() -> dict:
    """Clear compromise -- brute force, privilege escalation, mass exfiltration, anti-forensics."""
    return {
        "source": "MOCK",
        "verdict": "YES",
        "confidence": "HIGH",
        "confidence_explanation": (
            "A textbook attack chain is visible: failed login attempts from a known Tor exit "
            "node (185.220.101.34), followed by successful authentication, immediate "
            "self-escalation from read_only to read_write, rapid bulk download of 12 "
            "confidential files (~243 MB) in 11 minutes, and log deletion as anti-forensics. "
            "Every phase of the kill chain is explicitly evidenced."
        ),
        "suspect": "user_04",
        "attack_chain": [
            {
                "step": 1,
                "event_id": "evt_s3_001",
                "description": "First failed login attempt for user_04 from Tor exit node 185.220.101.34 at 02:47 (off-hours).",
                "confidence": "HIGH",
            },
            {
                "step": 2,
                "event_id": "evt_s3_002",
                "description": "Second failed login attempt one minute later from the same IP, indicating brute-force or credential-stuffing.",
                "confidence": "HIGH",
            },
            {
                "step": 3,
                "event_id": "evt_s3_003",
                "description": "Successful login at 02:49 from 185.220.101.34, completing initial access.",
                "confidence": "HIGH",
            },
            {
                "step": 4,
                "event_id": "evt_s3_004",
                "description": "Self-escalation of privileges from read_only to read_write within 3 minutes of login.",
                "confidence": "HIGH",
            },
            {
                "step": 5,
                "event_id": "evt_s3_005",
                "description": "Begin bulk exfiltration: downloaded customer_data_2025.csv (45 MB) from /data/finance/confidential/.",
                "confidence": "HIGH",
            },
            {
                "step": 6,
                "event_id": "evt_s3_006",
                "description": "Downloaded transaction_log_q1.csv (38 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 7,
                "event_id": "evt_s3_007",
                "description": "Downloaded salary_all_employees.xlsx (12 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 8,
                "event_id": "evt_s3_008",
                "description": "Downloaded loan_portfolio.xlsx (28 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 9,
                "event_id": "evt_s3_009",
                "description": "Downloaded credit_risk_model.xlsx (15 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 10,
                "event_id": "evt_s3_010",
                "description": "Downloaded swift_messages_march.csv (22 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 11,
                "event_id": "evt_s3_011",
                "description": "Downloaded audit_trail_2025.csv (31 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 12,
                "event_id": "evt_s3_012",
                "description": "Downloaded vendor_contracts.pdf (8 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 13,
                "event_id": "evt_s3_013",
                "description": "Downloaded board_minutes_q1.pdf (4 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 14,
                "event_id": "evt_s3_014",
                "description": "Downloaded tax_filings_2025.xlsx (19 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 15,
                "event_id": "evt_s3_015",
                "description": "Downloaded insurance_claims.csv (7 MB).",
                "confidence": "HIGH",
            },
            {
                "step": 16,
                "event_id": "evt_s3_016",
                "description": "Downloaded regulatory_correspondence.pdf (3 MB) -- final exfiltrated file.",
                "confidence": "HIGH",
            },
            {
                "step": 17,
                "event_id": "evt_s3_017",
                "description": "Anti-forensics: deleted /var/log/file_access.log to cover tracks.",
                "confidence": "HIGH",
            },
            {
                "step": 18,
                "event_id": "evt_s3_018",
                "description": "Logout at 03:10, completing the 23-minute intrusion.",
                "confidence": "HIGH",
            },
        ],
        "evidence_for": [
            "evt_s3_001",
            "evt_s3_002",
            "evt_s3_003",
            "evt_s3_004",
            "evt_s3_005",
            "evt_s3_006",
            "evt_s3_007",
            "evt_s3_008",
            "evt_s3_009",
            "evt_s3_010",
            "evt_s3_011",
            "evt_s3_012",
            "evt_s3_013",
            "evt_s3_014",
            "evt_s3_015",
            "evt_s3_016",
            "evt_s3_017",
            "evt_s3_018",
        ],
        "evidence_against": [],
        "gaps": [
            "Network-level data (DNS queries, NetFlow) would reveal where the exfiltrated data was sent.",
            "No endpoint telemetry to determine if malware or tools were deployed on the host.",
            "The file_access.log was deleted (evt_s3_017); additional access events may have existed.",
            "No MFA or session-token logs to determine how the attacker obtained valid credentials.",
        ],
        "narrative": (
            "user_04's account was compromised via credential attack from Tor exit node "
            "185.220.101.34 at 02:47. After two failed attempts and a successful login, the "
            "attacker escalated privileges from read_only to read_write and systematically "
            "exfiltrated 12 confidential financial files (~243 MB) in 11 minutes. The session "
            "concluded with deletion of the file access log as anti-forensics before logout "
            "at 03:10."
        ),
    }


def _mock_scenario_4() -> dict:
    """Slow exfiltration -- the 3-day escalation pattern that rules missed."""
    return {
        "source": "MOCK",
        "verdict": "YES",
        "confidence": "MEDIUM",
        "confidence_explanation": (
            "Over three days, user_03 systematically expanded access beyond their HR role "
            "into finance and engineering directories. Day 1 showed reconnaissance (reads "
            "only), Day 2 introduced targeted downloads of cross-department files, and Day 3 "
            "escalated to bulk downloads of 6 files across HR, finance, and engineering. "
            "The pattern is consistent with slow, methodical data collection designed to "
            "stay below per-day alerting thresholds. Individual daily activity appears "
            "plausible, but the 3-day trajectory reveals deliberate escalation. Confidence "
            "is MEDIUM because the privilege change (evt_s4_002) references a legitimate "
            "ticket (HR-2026-441) and each daily session is within normal hours."
        ),
        "suspect": "user_03",
        "attack_chain": [
            {
                "step": 1,
                "event_id": "evt_s4_002",
                "description": (
                    "Day 1 - Privilege expansion: user_03 obtained read access to "
                    "/data/finance/reports/ citing ticket HR-2026-441. This created the "
                    "access pathway exploited on subsequent days."
                ),
                "confidence": "MEDIUM",
            },
            {
                "step": 2,
                "event_id": "evt_s4_004",
                "description": (
                    "Day 1 - Reconnaissance: first cross-department read of "
                    "revenue_q1.xlsx in /data/finance/reports/. Read-only, no download -- "
                    "consistent with scoping valuable targets."
                ),
                "confidence": "MEDIUM",
            },
            {
                "step": 3,
                "event_id": "evt_s4_005",
                "description": (
                    "Day 1 - Continued reconnaissance: read expense_breakdown.xlsx, "
                    "second finance file in the same session."
                ),
                "confidence": "MEDIUM",
            },
            {
                "step": 4,
                "event_id": "evt_s4_010",
                "description": (
                    "Day 2 - First download: downloaded vendor_payments.xlsx (~911 KB) "
                    "from finance. Transition from read-only to data collection."
                ),
                "confidence": "MEDIUM",
            },
            {
                "step": 5,
                "event_id": "evt_s4_011",
                "description": (
                    "Day 2 - Lateral expansion: read candidate_pipeline.xlsx from "
                    "/data/engineering/hiring/, a directory outside both HR and finance "
                    "baselines."
                ),
                "confidence": "MEDIUM",
            },
            {
                "step": 6,
                "event_id": "evt_s4_012",
                "description": (
                    "Day 2 - Downloaded offer_letters_template.docx from engineering/hiring. "
                    "HR personnel may legitimately need this, but it extends the cross-department pattern."
                ),
                "confidence": "LOW",
            },
            {
                "step": 7,
                "event_id": "evt_s4_013",
                "description": (
                    "Day 2 - Read profit_loss_march.xlsx from finance. Third distinct "
                    "finance file across two days."
                ),
                "confidence": "MEDIUM",
            },
            {
                "step": 8,
                "event_id": "evt_s4_017",
                "description": (
                    "Day 3 - Downloaded salary_bands.xlsx from /data/hr/ (own department). "
                    "Sensitive compensation data. Previously only read on the same day."
                ),
                "confidence": "LOW",
            },
            {
                "step": 9,
                "event_id": "evt_s4_018",
                "description": (
                    "Day 3 - Downloaded revenue_q1.xlsx from finance. This file was "
                    "only read on Day 1 (evt_s4_004) -- returning to download previously "
                    "scouted files is a strong exfiltration indicator."
                ),
                "confidence": "HIGH",
            },
            {
                "step": 10,
                "event_id": "evt_s4_019",
                "description": (
                    "Day 3 - Downloaded budget_forecast.xlsx from finance. Previously "
                    "only read on Day 2 (evt_s4_009)."
                ),
                "confidence": "HIGH",
            },
            {
                "step": 11,
                "event_id": "evt_s4_020",
                "description": (
                    "Day 3 - Downloaded candidate_pipeline.xlsx from engineering/hiring. "
                    "Previously read on Day 2 (evt_s4_011). Same read-then-download pattern."
                ),
                "confidence": "HIGH",
            },
            {
                "step": 12,
                "event_id": "evt_s4_021",
                "description": (
                    "Day 3 - Downloaded expense_breakdown.xlsx from finance. Previously "
                    "read on Day 1 (evt_s4_005). Fourth file following the scout-then-collect pattern."
                ),
                "confidence": "HIGH",
            },
            {
                "step": 13,
                "event_id": "evt_s4_022",
                "description": (
                    "Day 3 - Downloaded performance_reviews_2025.xlsx (~1.3 MB) from HR. "
                    "Highly sensitive personnel data downloaded at the end of the collection day."
                ),
                "confidence": "MEDIUM",
            },
        ],
        "evidence_for": [
            "evt_s4_002",
            "evt_s4_004",
            "evt_s4_005",
            "evt_s4_010",
            "evt_s4_011",
            "evt_s4_012",
            "evt_s4_013",
            "evt_s4_017",
            "evt_s4_018",
            "evt_s4_019",
            "evt_s4_020",
            "evt_s4_021",
            "evt_s4_022",
        ],
        "evidence_against": [
            "evt_s4_002",
            "evt_s4_003",
            "evt_s4_008",
            "evt_s4_016",
        ],
        "gaps": [
            "No data exfiltration channel is visible -- USB, email, or cloud upload logs would confirm whether downloaded files left the organization.",
            "Ticket HR-2026-441 should be verified: was it a legitimate request or fabricated justification?",
            "No manager approval logs for the cross-department access grant.",
            "user_03's download history for the preceding 30 days would clarify whether this 3-day pattern is anomalous or part of a periodic review cycle.",
            "Endpoint DLP logs would show if files were copied to removable media or uploaded externally.",
        ],
        "narrative": (
            "user_03 executed a methodical 3-day data collection campaign that individual "
            "daily rule checks failed to flag as a coherent threat. Day 1 established "
            "cross-department access via a privilege request and performed read-only "
            "reconnaissance of finance files. Day 2 introduced targeted downloads and "
            "expanded laterally into engineering/hiring. Day 3 returned to download every "
            "file previously scouted, collecting sensitive financial, HR, and engineering "
            "data (~5 MB total). The read-then-download pattern across days is the strongest "
            "indicator of premeditated insider data collection."
        ),
    }


def call_mock_llm(prompt: str, scenario_num: int) -> dict:
    """Return a realistic mock LLM response for the given scenario.

    Args:
        prompt: The prompt (unused but kept for interface consistency).
        scenario_num: The scenario number (1-4).

    Returns:
        A dict matching the expected analysis JSON structure with a "source": "MOCK" field.
    """
    mock_handlers = {
        1: _mock_scenario_1,
        2: _mock_scenario_2,
        3: _mock_scenario_3,
        4: _mock_scenario_4,
    }
    handler = mock_handlers.get(scenario_num)
    if handler is None:
        return {
            "source": "MOCK",
            "error": f"No mock response defined for scenario {scenario_num}",
        }
    return handler()


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def parse_llm_response(raw_response: str) -> dict:
    """Extract JSON from an LLM response string.

    Handles markdown code blocks (```json ... ```), plain JSON, and other
    common LLM output wrappers.

    Args:
        raw_response: The raw string returned by the LLM.

    Returns:
        Parsed dict, or {"error": "parse_failed", "raw": raw_response} on failure.
    """
    if isinstance(raw_response, dict):
        return raw_response

    text = raw_response.strip()

    # Try extracting from markdown code block first
    code_block_match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
    if code_block_match:
        try:
            return json.loads(code_block_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try parsing the whole string as JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try finding a JSON object in the text
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    return {"error": "parse_failed", "raw": raw_response}


# ---------------------------------------------------------------------------
# High-level analysis functions
# ---------------------------------------------------------------------------

async def analyze_scenario(scenario_num: int, use_mock: bool = False) -> dict:
    """Analyze a single scenario using either mock or real LLM.

    Args:
        scenario_num: The scenario number (1-4).
        use_mock: If True, use mock responses instead of the real LLM.

    Returns:
        Parsed analysis result dict.
    """
    prompt = build_scenario_prompt(scenario_num)

    if use_mock:
        result = call_mock_llm(prompt, scenario_num)
    else:
        result = await call_modal_llm(prompt, system_prompt=LLM_SYSTEM_PROMPT)

    # Ensure output directory exists
    output_dir = PROJECT_ROOT / "data" / "llm_responses"
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save response
    output_path = output_dir / f"scenario_{scenario_num}_response.json"
    with open(output_path, "w") as f:
        json.dump(result, f, indent=2)

    return result


async def analyze_all(use_mock: bool = False) -> dict:
    """Analyze all scenarios found in data/scenarios/.

    Args:
        use_mock: If True, use mock responses instead of the real LLM.

    Returns:
        Dict keyed by scenario number (int) with analysis results as values.
    """
    scenario_files = sorted((PROJECT_ROOT / "data" / "scenarios").glob("scenario_*.json"))
    scenario_nums = [int(f.stem.split("_")[1]) for f in scenario_files]

    results = {}
    for scenario_num in scenario_nums:
        results[scenario_num] = await analyze_scenario(scenario_num, use_mock=use_mock)
    return results


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    endpoint = os.getenv("MODAL_ENDPOINT", "")
    use_mock = (
        not endpoint
        or "your-modal" in endpoint
    )

    if use_mock:
        print("MODAL_ENDPOINT not configured -- running with mock responses.\n")
    else:
        print(f"Using Modal endpoint: {endpoint}\n")

    async def main():
        results = await analyze_all(use_mock=use_mock)
        for scenario_num, result in sorted(results.items()):
            print(f"{'=' * 60}")
            print(f"SCENARIO {scenario_num}")
            print(f"{'=' * 60}")
            print(f"  Verdict:    {result.get('verdict', 'N/A')}")
            print(f"  Confidence: {result.get('confidence', 'N/A')}")
            print(f"  Suspect:    {result.get('suspect', 'None')}")
            print(f"  Source:     {result.get('source', 'LLM')}")
            narrative = result.get("narrative", "")
            if narrative:
                print(f"  Narrative:  {narrative[:120]}...")
            chain = result.get("attack_chain", [])
            if chain:
                print(f"  Attack chain steps: {len(chain)}")
            print()

    asyncio.run(main())
