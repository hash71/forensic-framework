"""
Timeline reconstruction module for forensic investigation framework.

Builds chronological timelines from normalized events, with grouping
by user and session for investigative analysis.
"""

import json
from collections import defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
NORMALIZED_DIR = PROJECT_ROOT / "data" / "normalized"


def build_timeline(events: list[dict]) -> list[dict]:
    """Sort events by timestamp and return the sorted list."""
    return sorted(events, key=lambda e: e.get("timestamp", ""))


def group_by_user(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by user field. Return dict keyed by user_id."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        user = event.get("user") or "unknown_user"
        groups[user].append(event)
    return dict(groups)


def group_by_session(events: list[dict]) -> dict[str, list[dict]]:
    """Group events by session_id. Null session_ids go under 'no_session'."""
    groups: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        session_id = event.get("session_id") or "no_session"
        groups[session_id].append(event)
    return dict(groups)


def build_scenario_timeline(scenario_num: int) -> dict:
    """
    Load normalized events for a scenario, build timeline,
    group by user and session. Return structured result.
    """
    events_path = NORMALIZED_DIR / f"scenario_{scenario_num}_events.json"
    with open(events_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    timeline = build_timeline(events)
    by_user = group_by_user(timeline)
    by_session = group_by_session(timeline)

    time_range = {}
    if timeline:
        time_range = {
            "start": timeline[0]["timestamp"],
            "end": timeline[-1]["timestamp"],
        }

    return {
        "scenario": scenario_num,
        "total_events": len(timeline),
        "timeline": timeline,
        "by_user": by_user,
        "by_session": by_session,
        "time_range": time_range,
    }


def build_all_timelines() -> dict:
    """
    Build timelines for all scenarios found in the normalized directory.
    Save each to data/normalized/scenario_{N}_timeline.json.
    Return dict keyed by scenario number.
    """
    results: dict[int, dict] = {}

    scenario_files = sorted(NORMALIZED_DIR.glob("scenario_*_events.json"))
    for path in scenario_files:
        # Extract scenario number from filename like scenario_4_events.json
        stem = path.stem  # scenario_4_events
        parts = stem.split("_")
        try:
            scenario_num = int(parts[1])
        except (IndexError, ValueError):
            continue

        result = build_scenario_timeline(scenario_num)
        results[scenario_num] = result

        # Save timeline to JSON
        output_path = NORMALIZED_DIR / f"scenario_{scenario_num}_timeline.json"
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    return results


if __name__ == "__main__":
    all_timelines = build_all_timelines()

    print("=" * 70)
    print("FORENSIC TIMELINE RECONSTRUCTION - SUMMARY")
    print("=" * 70)

    for scenario_num in sorted(all_timelines.keys()):
        tl = all_timelines[scenario_num]
        users = sorted(tl["by_user"].keys())
        sessions = sorted(tl["by_session"].keys())
        time_range = tl["time_range"]

        print(f"\n--- Scenario {scenario_num} ---")
        print(f"  Total events : {tl['total_events']}")
        print(f"  Time range   : {time_range.get('start', 'N/A')} -> {time_range.get('end', 'N/A')}")
        print(f"  Users ({len(users)}): {', '.join(users)}")
        print(f"  Sessions ({len(sessions)}): {', '.join(sessions)}")

    # Print full Scenario 4 timeline
    if 4 in all_timelines:
        print("\n" + "=" * 70)
        print("SCENARIO 4 - FULL TIMELINE (3-day progression)")
        print("=" * 70)

        for event in all_timelines[4]["timeline"]:
            ts = event.get("timestamp", "N/A")
            user = event.get("user", "N/A")
            action = event.get("action", "N/A")
            resource = event.get("resource", "")
            status = event.get("status", "")
            severity = event.get("severity", "")
            source_ip = event.get("source_ip", "")
            session_id = event.get("session_id", "")

            print(
                f"  [{ts}] user={user} action={action} "
                f"resource={resource or '-'} status={status} "
                f"severity={severity} ip={source_ip} session={session_id}"
            )
    else:
        print("\nScenario 4 not found - skipping detailed timeline.")

    print(f"\nTimeline files saved to: {NORMALIZED_DIR}")
