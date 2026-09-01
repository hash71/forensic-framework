"""
Hallucination checker for LLM responses in forensic investigations.

Validates LLM-generated analysis against actual normalized event evidence
to detect hallucinated event references, timeline errors, unsupported claims,
and fabricated actor references.
"""

import json
import re
from pathlib import Path
from datetime import datetime, timedelta

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def load_scenario_events(scenario_num: int) -> dict[str, dict]:
    """Load normalized events for a scenario, returning a dict keyed by event_id."""
    events_path = PROJECT_ROOT / "data" / "normalized" / f"scenario_{scenario_num}_events.json"
    if not events_path.exists():
        raise FileNotFoundError(f"Normalized events not found: {events_path}")

    with open(events_path, "r") as f:
        events_list = json.load(f)

    return {event["event_id"]: event for event in events_list}


def check_event_references(llm_response: dict, valid_events: dict) -> dict:
    """Check all event_id references in the LLM response against actual events."""
    referenced_ids: list[str] = []

    # Collect event_ids from attack_chain
    for step in llm_response.get("attack_chain", []):
        event_id = step.get("event_id")
        if event_id:
            referenced_ids.append(event_id)

    # Collect from evidence_for and evidence_against
    referenced_ids.extend(llm_response.get("evidence_for", []))
    referenced_ids.extend(llm_response.get("evidence_against", []))

    invalid = [eid for eid in referenced_ids if eid not in valid_events]

    return {
        "total_references": len(referenced_ids),
        "valid_references": len(referenced_ids) - len(invalid),
        "invalid_references": invalid,
        "hallucinated_events": len(invalid),
    }


def check_timeline_correctness(llm_response: dict, valid_events: dict) -> dict:
    """Check if attack_chain steps are in chronological order based on actual timestamps."""
    attack_chain = llm_response.get("attack_chain", [])

    if not attack_chain:
        return {
            "chain_length": 0,
            "chronologically_correct": True,
            "out_of_order_steps": [],
        }

    # Build list of (step_number, timestamp) for steps that reference valid events
    step_timestamps: list[tuple[int, datetime]] = []
    for step in attack_chain:
        event_id = step.get("event_id")
        step_num = step.get("step")
        if event_id and event_id in valid_events:
            ts_str = valid_events[event_id].get("timestamp", "")
            if ts_str:
                ts = datetime.fromisoformat(ts_str)
                step_timestamps.append((step_num, ts))

    out_of_order: list[int] = []
    for i in range(1, len(step_timestamps)):
        if step_timestamps[i][1] < step_timestamps[i - 1][1]:
            out_of_order.append(step_timestamps[i][0])

    return {
        "chain_length": len(attack_chain),
        "chronologically_correct": len(out_of_order) == 0,
        "out_of_order_steps": out_of_order,
    }


def check_unsupported_claims(llm_response: dict) -> dict:
    """Count claims that lack event_id references."""
    attack_chain = llm_response.get("attack_chain", [])
    narrative = llm_response.get("narrative", "")

    # Check attack_chain steps for event_id support
    supported_steps = 0
    unsupported_steps = 0
    for step in attack_chain:
        if step.get("event_id"):
            supported_steps += 1
        else:
            unsupported_steps += 1

    # Check narrative for event_id mentions
    narrative_has_evidence = bool(re.search(r"evt_\w+", narrative))

    # Narrative counts as one claim
    total_claims = len(attack_chain) + (1 if narrative else 0)
    supported = supported_steps + (1 if narrative and narrative_has_evidence else 0)
    unsupported = total_claims - supported

    evidence_grounding = (supported / total_claims * 100.0) if total_claims > 0 else 100.0

    return {
        "total_claims": total_claims,
        "supported_claims": supported,
        "unsupported_claims": unsupported,
        "evidence_grounding": round(evidence_grounding, 2),
    }


def check_actor_references(llm_response: dict, valid_events: dict) -> dict:
    """Check if the suspect user actually appears in the referenced events."""
    suspect = llm_response.get("suspect")

    actors_in_events = sorted(
        {event.get("user") for event in valid_events.values() if event.get("user")}
    )

    suspect_in_events = suspect in actors_in_events if suspect else False

    return {
        "suspect": suspect,
        "suspect_in_events": suspect_in_events,
        "actors_in_events": actors_in_events,
    }


def check_temporal_claims(llm_response: dict, valid_events: dict) -> dict:
    """Parse attack chain descriptions for temporal claims and verify against actual timestamps.

    Looks for phrases like "X minutes after", "within N hours", "shortly after",
    extracts referenced event_ids, and verifies the claimed time gap matches
    actual timestamps (within +/-5 minute tolerance).

    Returns:
        Dict with temporal_claims_checked, temporal_claims_valid, and temporal_errors.
    """
    temporal_errors: list[dict] = []
    claims_checked = 0
    claims_valid = 0

    # Patterns that express temporal relationships
    # e.g. "3 minutes after", "within 2 hours", "shortly after", "11 minutes"
    temporal_patterns = [
        # "N minutes/hours/seconds after/before/later"
        re.compile(
            r"(\d+)\s*(minutes?|hours?|seconds?)\s*(?:after|before|later|of)",
            re.IGNORECASE,
        ),
        # "within N minutes/hours"
        re.compile(
            r"within\s+(\d+)\s*(minutes?|hours?|seconds?)",
            re.IGNORECASE,
        ),
        # "shortly after" (implies < 10 minutes)
        re.compile(r"shortly\s+after", re.IGNORECASE),
    ]

    # Event ID pattern
    event_id_pattern = re.compile(r"evt_\w+")

    # Check attack chain descriptions
    attack_chain = llm_response.get("attack_chain", [])
    for step in attack_chain:
        description = step.get("description", "")
        step_event_id = step.get("event_id")

        for pattern in temporal_patterns:
            matches = pattern.finditer(description)
            for match in matches:
                claims_checked += 1

                # Extract all event_ids mentioned in this description
                mentioned_ids = event_id_pattern.findall(description)
                # Include the step's own event_id
                all_relevant_ids = set(mentioned_ids)
                if step_event_id:
                    all_relevant_ids.add(step_event_id)

                # Need at least 2 event_ids to verify a temporal claim
                valid_ids = [eid for eid in all_relevant_ids if eid in valid_events]
                if len(valid_ids) < 2:
                    # Can't verify without two known events; skip
                    claims_valid += 1  # Give benefit of the doubt
                    continue

                # Parse the claimed duration
                if match.group(0).lower().startswith("shortly"):
                    claimed_minutes = 10.0  # "shortly after" implies < 10 min
                    is_shortly = True
                else:
                    amount = float(match.group(1))
                    unit = match.group(2).lower()
                    if unit.startswith("hour"):
                        claimed_minutes = amount * 60
                    elif unit.startswith("second"):
                        claimed_minutes = amount / 60
                    else:
                        claimed_minutes = amount
                    is_shortly = False

                # Get timestamps and compute actual gap
                timestamps = []
                for eid in valid_ids:
                    ts_str = valid_events[eid].get("timestamp", "")
                    if ts_str:
                        timestamps.append(datetime.fromisoformat(ts_str))

                if len(timestamps) < 2:
                    claims_valid += 1
                    continue

                timestamps.sort()
                actual_gap_minutes = (timestamps[-1] - timestamps[0]).total_seconds() / 60

                # Verify with tolerance
                tolerance = 5.0  # minutes
                if is_shortly:
                    if actual_gap_minutes <= claimed_minutes + tolerance:
                        claims_valid += 1
                    else:
                        temporal_errors.append({
                            "step": step.get("step"),
                            "claim": match.group(0),
                            "claimed_minutes": claimed_minutes,
                            "actual_minutes": round(actual_gap_minutes, 2),
                            "event_ids": valid_ids,
                            "error": f"'shortly after' but actual gap is {actual_gap_minutes:.1f} minutes",
                        })
                else:
                    if abs(actual_gap_minutes - claimed_minutes) <= tolerance:
                        claims_valid += 1
                    else:
                        temporal_errors.append({
                            "step": step.get("step"),
                            "claim": match.group(0),
                            "claimed_minutes": claimed_minutes,
                            "actual_minutes": round(actual_gap_minutes, 2),
                            "event_ids": valid_ids,
                            "error": (
                                f"Claimed {claimed_minutes:.0f} min but actual gap is "
                                f"{actual_gap_minutes:.1f} min"
                            ),
                        })

    # Also check the narrative
    narrative = llm_response.get("narrative", "")
    for pattern in temporal_patterns:
        matches = pattern.finditer(narrative)
        for match in matches:
            claims_checked += 1
            # Extract event_ids near the temporal claim
            mentioned_ids = event_id_pattern.findall(narrative)
            valid_ids = [eid for eid in mentioned_ids if eid in valid_events]

            if len(valid_ids) < 2:
                claims_valid += 1
                continue

            if match.group(0).lower().startswith("shortly"):
                claimed_minutes = 10.0
                is_shortly = True
            else:
                amount = float(match.group(1))
                unit = match.group(2).lower()
                if unit.startswith("hour"):
                    claimed_minutes = amount * 60
                elif unit.startswith("second"):
                    claimed_minutes = amount / 60
                else:
                    claimed_minutes = amount
                is_shortly = False

            timestamps = []
            for eid in valid_ids:
                ts_str = valid_events[eid].get("timestamp", "")
                if ts_str:
                    timestamps.append(datetime.fromisoformat(ts_str))

            if len(timestamps) < 2:
                claims_valid += 1
                continue

            timestamps.sort()
            actual_gap_minutes = (timestamps[-1] - timestamps[0]).total_seconds() / 60
            tolerance = 5.0

            if is_shortly:
                if actual_gap_minutes <= claimed_minutes + tolerance:
                    claims_valid += 1
                else:
                    temporal_errors.append({
                        "location": "narrative",
                        "claim": match.group(0),
                        "claimed_minutes": claimed_minutes,
                        "actual_minutes": round(actual_gap_minutes, 2),
                        "event_ids": valid_ids,
                        "error": f"'shortly after' but actual gap is {actual_gap_minutes:.1f} minutes",
                    })
            else:
                if abs(actual_gap_minutes - claimed_minutes) <= tolerance:
                    claims_valid += 1
                else:
                    temporal_errors.append({
                        "location": "narrative",
                        "claim": match.group(0),
                        "claimed_minutes": claimed_minutes,
                        "actual_minutes": round(actual_gap_minutes, 2),
                        "event_ids": valid_ids,
                        "error": (
                            f"Claimed {claimed_minutes:.0f} min but actual gap is "
                            f"{actual_gap_minutes:.1f} min"
                        ),
                    })

    return {
        "temporal_claims_checked": claims_checked,
        "temporal_claims_valid": claims_valid,
        "temporal_errors": temporal_errors,
    }


def check_volume_claims(llm_response: dict, valid_events: dict) -> dict:
    """Parse narrative and attack chain for volume claims and verify against evidence.

    Checks claims about file counts, file sizes, and time spans against actual
    event data.

    Returns:
        Dict with volume_claims_checked, volume_claims_valid, and volume_errors.
    """
    volume_errors: list[dict] = []
    claims_checked = 0
    claims_valid = 0

    # Collect all text to scan from attack chain descriptions and narrative
    text_sources: list[tuple[str, str]] = []
    for step in llm_response.get("attack_chain", []):
        desc = step.get("description", "")
        if desc:
            text_sources.append((f"attack_chain step {step.get('step', '?')}", desc))
    narrative = llm_response.get("narrative", "")
    if narrative:
        text_sources.append(("narrative", narrative))

    # Patterns for volume claims
    file_count_pattern = re.compile(r"(\d+)\s*(?:files?|documents?)", re.IGNORECASE)
    file_size_pattern = re.compile(
        r"(\d+(?:\.\d+)?)\s*(bytes?|KB|MB|GB|TB)", re.IGNORECASE
    )
    # Specific size in parentheses like "(45 MB)" or "~243 MB"
    specific_size_pattern = re.compile(
        r"[~(]?\s*(\d+(?:\.\d+)?)\s*(bytes?|KB|MB|GB)\s*\)?", re.IGNORECASE
    )
    time_span_pattern = re.compile(
        r"(?:over|within|in|across)\s+(\d+)\s*(minutes?|hours?|days?|weeks?)",
        re.IGNORECASE,
    )

    # Gather actual evidence stats
    download_events = [
        e for e in valid_events.values() if e.get("action") == "file_download"
    ]
    all_events_list = list(valid_events.values())

    # Actual file count for downloads
    actual_download_count = len(download_events)

    # Actual total size (sum of file_size_bytes from metadata)
    actual_total_bytes = 0
    for evt in download_events:
        metadata = evt.get("metadata", {}) or {}
        size = metadata.get("file_size_bytes")
        if size is not None:
            actual_total_bytes += size

    # Actual time span of all events
    all_timestamps = []
    for evt in all_events_list:
        ts_str = evt.get("timestamp", "")
        if ts_str:
            all_timestamps.append(datetime.fromisoformat(ts_str))
    if all_timestamps:
        all_timestamps.sort()
        actual_span = all_timestamps[-1] - all_timestamps[0]
    else:
        actual_span = timedelta(0)

    def _bytes_from_claim(amount: float, unit: str) -> float:
        unit_lower = unit.lower().rstrip("s")
        multipliers = {"byte": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}
        return amount * multipliers.get(unit_lower, 1)

    for location, text in text_sources:
        # Check file count claims
        for match in file_count_pattern.finditer(text):
            claimed_count = int(match.group(1))
            # Only check if this looks like a download/exfiltration count claim
            context = text[max(0, match.start() - 40):match.end() + 40].lower()
            if any(kw in context for kw in ["download", "exfiltrat", "collect", "stole", "bulk"]):
                claims_checked += 1
                # Allow tolerance of +/- 1
                if abs(claimed_count - actual_download_count) <= 1:
                    claims_valid += 1
                else:
                    volume_errors.append({
                        "location": location,
                        "claim": match.group(0),
                        "claimed_count": claimed_count,
                        "actual_count": actual_download_count,
                        "error": (
                            f"Claimed {claimed_count} files but found "
                            f"{actual_download_count} download events"
                        ),
                    })

        # Check file size claims (aggregate sizes like "~243 MB")
        for match in specific_size_pattern.finditer(text):
            claimed_amount = float(match.group(1))
            claimed_unit = match.group(2)
            claimed_bytes = _bytes_from_claim(claimed_amount, claimed_unit)

            # Only check aggregate size claims (not individual file sizes in step descriptions)
            # Heuristic: if context mentions "total" or is in the narrative
            context = text[max(0, match.start() - 60):match.end() + 60].lower()
            is_aggregate = (
                location == "narrative"
                or any(kw in context for kw in ["total", "~", "approximately"])
            )

            if is_aggregate and actual_total_bytes > 0:
                claims_checked += 1
                # Allow 20% tolerance for size claims
                tolerance_ratio = 0.20
                if abs(claimed_bytes - actual_total_bytes) <= actual_total_bytes * tolerance_ratio:
                    claims_valid += 1
                elif claimed_bytes > actual_total_bytes * 2 or claimed_bytes < actual_total_bytes * 0.5:
                    volume_errors.append({
                        "location": location,
                        "claim": match.group(0),
                        "claimed_bytes": claimed_bytes,
                        "actual_bytes": actual_total_bytes,
                        "error": (
                            f"Claimed {match.group(0)} but actual total is "
                            f"{actual_total_bytes / (1024**2):.1f} MB"
                        ),
                    })
                else:
                    claims_valid += 1  # Within reasonable range

        # Check time span claims
        for match in time_span_pattern.finditer(text):
            claimed_amount = int(match.group(1))
            claimed_unit = match.group(2).lower()

            claims_checked += 1

            if claimed_unit.startswith("minute"):
                claimed_span = timedelta(minutes=claimed_amount)
            elif claimed_unit.startswith("hour"):
                claimed_span = timedelta(hours=claimed_amount)
            elif claimed_unit.startswith("day"):
                claimed_span = timedelta(days=claimed_amount)
            elif claimed_unit.startswith("week"):
                claimed_span = timedelta(weeks=claimed_amount)
            else:
                claims_valid += 1
                continue

            # Allow reasonable tolerance based on unit
            if claimed_unit.startswith("minute"):
                tolerance = timedelta(minutes=5)
            elif claimed_unit.startswith("hour"):
                tolerance = timedelta(hours=1)
            else:
                tolerance = timedelta(days=1)

            if abs(actual_span - claimed_span) <= tolerance:
                claims_valid += 1
            else:
                volume_errors.append({
                    "location": location,
                    "claim": match.group(0),
                    "claimed_span": str(claimed_span),
                    "actual_span": str(actual_span),
                    "error": (
                        f"Claimed {match.group(0)} but actual event span is "
                        f"{actual_span}"
                    ),
                })

    return {
        "volume_claims_checked": claims_checked,
        "volume_claims_valid": claims_valid,
        "volume_errors": volume_errors,
    }


def check_entity_consistency(llm_response: dict, valid_events: dict) -> dict:
    """Check that all user IDs, IP addresses, and file paths in the response appear in evidence.

    Extracts user mentions (user_01, user_02, etc.), IP addresses, and file paths
    from narrative and attack chain, then verifies each against the event data.

    Returns:
        Dict with entities_checked, entities_valid, and unknown_entities.
    """
    unknown_entities: list[dict] = []
    entities_checked = 0
    entities_valid = 0

    # Collect all text to scan
    all_text = ""
    narrative = llm_response.get("narrative", "")
    if narrative:
        all_text += narrative + " "
    for step in llm_response.get("attack_chain", []):
        desc = step.get("description", "")
        if desc:
            all_text += desc + " "

    # Build sets of known entities from valid_events
    known_users: set[str] = set()
    known_ips: set[str] = set()
    known_paths: set[str] = set()

    for evt in valid_events.values():
        user = evt.get("user")
        if user:
            known_users.add(user)
        ip = evt.get("source_ip")
        if ip:
            known_ips.add(ip)
        resource = evt.get("resource")
        if resource:
            known_paths.add(resource)

    # Extract and check user mentions (pattern: user_XX or user_XXX)
    user_pattern = re.compile(r"\buser_\d+\b")
    mentioned_users = set(user_pattern.findall(all_text))
    for user in mentioned_users:
        entities_checked += 1
        if user in known_users:
            entities_valid += 1
        else:
            unknown_entities.append({
                "type": "user",
                "value": user,
                "error": f"User '{user}' not found in any event",
            })

    # Extract and check IP addresses
    ip_pattern = re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    )
    mentioned_ips = set(ip_pattern.findall(all_text))
    for ip in mentioned_ips:
        entities_checked += 1
        if ip in known_ips:
            entities_valid += 1
        else:
            unknown_entities.append({
                "type": "ip_address",
                "value": ip,
                "error": f"IP address '{ip}' not found in any event",
            })

    # Extract and check file paths (pattern: /data/... or /var/...)
    path_pattern = re.compile(r"(/(?:data|var|etc|tmp|home|opt)/[\w./\-]+)")
    mentioned_paths = set(path_pattern.findall(all_text))
    for path in mentioned_paths:
        entities_checked += 1
        # Check exact match or if any known path starts with/contains this path
        if path in known_paths or any(kp.startswith(path) or path.startswith(kp) for kp in known_paths):
            entities_valid += 1
        else:
            unknown_entities.append({
                "type": "file_path",
                "value": path,
                "error": f"Path '{path}' not found in any event resource",
            })

    return {
        "entities_checked": entities_checked,
        "entities_valid": entities_valid,
        "unknown_entities": unknown_entities,
    }


def run_hallucination_check(llm_response: dict, scenario_num: int) -> dict:
    """Run all hallucination checks and return a combined report."""
    valid_events = load_scenario_events(scenario_num)

    event_refs = check_event_references(llm_response, valid_events)
    timeline = check_timeline_correctness(llm_response, valid_events)
    unsupported = check_unsupported_claims(llm_response)
    actors = check_actor_references(llm_response, valid_events)
    temporal = check_temporal_claims(llm_response, valid_events)
    volume = check_volume_claims(llm_response, valid_events)
    entity = check_entity_consistency(llm_response, valid_events)

    hallucination_count = (
        event_refs["hallucinated_events"]
        + len(timeline["out_of_order_steps"])
        + unsupported["unsupported_claims"]
        + len(temporal["temporal_errors"])
        + len(volume["volume_errors"])
        + len(entity["unknown_entities"])
    )

    return {
        "scenario": scenario_num,
        "event_references": event_refs,
        "timeline_correctness": timeline,
        "unsupported_claims": unsupported,
        "actor_references": actors,
        "temporal_claims": temporal,
        "volume_claims": volume,
        "entity_consistency": entity,
        "hallucination_count": hallucination_count,
        "hallucination_free": hallucination_count == 0,
    }


if __name__ == "__main__":
    responses_dir = PROJECT_ROOT / "data" / "llm_responses"

    if not responses_dir.exists():
        print(f"LLM responses directory not found: {responses_dir}")
        raise SystemExit(1)

    response_files = sorted(responses_dir.glob("scenario_*_response.json"))

    if not response_files:
        print("No LLM response files found.")
        raise SystemExit(0)

    for response_file in response_files:
        # Extract scenario number from filename
        match = re.search(r"scenario_(\d+)_response\.json", response_file.name)
        if not match:
            continue
        scenario_num = int(match.group(1))

        print(f"\n{'=' * 60}")
        print(f"Hallucination Check - Scenario {scenario_num}")
        print(f"{'=' * 60}")

        with open(response_file, "r") as f:
            llm_response = json.load(f)

        try:
            report = run_hallucination_check(llm_response, scenario_num)
        except FileNotFoundError as e:
            print(f"  Skipping: {e}")
            continue

        # Event references
        er = report["event_references"]
        print(f"\nEvent References:")
        print(f"  Total: {er['total_references']}, Valid: {er['valid_references']}, "
              f"Hallucinated: {er['hallucinated_events']}")
        if er["invalid_references"]:
            print(f"  Invalid IDs: {er['invalid_references']}")

        # Timeline
        tc = report["timeline_correctness"]
        print(f"\nTimeline Correctness:")
        print(f"  Chain length: {tc['chain_length']}, "
              f"Chronological: {tc['chronologically_correct']}")
        if tc["out_of_order_steps"]:
            print(f"  Out-of-order steps: {tc['out_of_order_steps']}")

        # Unsupported claims
        uc = report["unsupported_claims"]
        print(f"\nUnsupported Claims:")
        print(f"  Total claims: {uc['total_claims']}, Supported: {uc['supported_claims']}, "
              f"Unsupported: {uc['unsupported_claims']}")
        print(f"  Evidence grounding: {uc['evidence_grounding']}%")

        # Actor references
        ar = report["actor_references"]
        print(f"\nActor References:")
        print(f"  Suspect: {ar['suspect']}, In events: {ar['suspect_in_events']}")
        print(f"  Actors in events: {ar['actors_in_events']}")

        # Summary
        print(f"\n--- Summary ---")
        print(f"  Hallucination count: {report['hallucination_count']}")
        print(f"  Hallucination free: {report['hallucination_free']}")
