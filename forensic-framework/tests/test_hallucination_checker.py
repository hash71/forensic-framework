"""
Tests for app.llm.hallucination_checker — 6+ tests.
"""

from app.llm.hallucination_checker import (
    check_event_references,
    check_timeline_correctness,
    check_unsupported_claims,
    check_actor_references,
)


def _build_valid_events(ids_and_timestamps, user="user_04"):
    """Helper: build a valid_events dict keyed by event_id."""
    return {
        eid: {
            "event_id": eid,
            "timestamp": ts,
            "user": user,
            "action": "login",
            "source_type": "auth",
        }
        for eid, ts in ids_and_timestamps
    }


# ── check_event_references ───────────────────────────────────────────────────

def test_all_valid_references(sample_llm_response_attack, sample_normalized_events):
    """All event_ids in the LLM response exist in valid_events -> no hallucinations."""
    valid_events = {e["event_id"]: e for e in sample_normalized_events}
    result = check_event_references(sample_llm_response_attack, valid_events)

    assert result["hallucinated_events"] == 0
    assert result["invalid_references"] == []
    assert result["total_references"] > 0


def test_invalid_event_reference(sample_llm_response_hallucinated, sample_normalized_events):
    """evt_s99_001 and evt_s99_002 do not exist -> should be flagged."""
    valid_events = {e["event_id"]: e for e in sample_normalized_events}
    result = check_event_references(sample_llm_response_hallucinated, valid_events)

    assert result["hallucinated_events"] >= 1
    assert "evt_s99_001" in result["invalid_references"]
    assert "evt_s99_002" in result["invalid_references"]


# ── check_timeline_correctness ───────────────────────────────────────────────

def test_timeline_chronological():
    """Steps in chronological order should pass."""
    valid_events = _build_valid_events([
        ("evt_s0_001", "2026-04-01T02:47:00+06:00"),
        ("evt_s0_002", "2026-04-01T02:49:00+06:00"),
        ("evt_s0_003", "2026-04-01T02:52:00+06:00"),
    ])
    llm_response = {
        "attack_chain": [
            {"step": 1, "event_id": "evt_s0_001", "description": "Step 1"},
            {"step": 2, "event_id": "evt_s0_002", "description": "Step 2"},
            {"step": 3, "event_id": "evt_s0_003", "description": "Step 3"},
        ],
    }
    result = check_timeline_correctness(llm_response, valid_events)

    assert result["chronologically_correct"] is True
    assert result["out_of_order_steps"] == []
    assert result["chain_length"] == 3


def test_timeline_out_of_order():
    """Steps listed out of chronological order should be detected."""
    valid_events = _build_valid_events([
        ("evt_s0_001", "2026-04-01T02:47:00+06:00"),
        ("evt_s0_002", "2026-04-01T02:49:00+06:00"),
        ("evt_s0_003", "2026-04-01T02:52:00+06:00"),
    ])
    llm_response = {
        "attack_chain": [
            {"step": 1, "event_id": "evt_s0_003", "description": "Step 1"},
            {"step": 2, "event_id": "evt_s0_001", "description": "Step 2"},
            {"step": 3, "event_id": "evt_s0_002", "description": "Step 3"},
        ],
    }
    result = check_timeline_correctness(llm_response, valid_events)

    assert result["chronologically_correct"] is False
    assert len(result["out_of_order_steps"]) >= 1


# ── check_unsupported_claims ─────────────────────────────────────────────────

def test_unsupported_claims():
    """A chain step without event_id should count as unsupported."""
    llm_response = {
        "attack_chain": [
            {"step": 1, "event_id": "evt_s0_001", "description": "Step with evidence"},
            {"step": 2, "description": "Step without evidence"},
            {"step": 3, "event_id": "evt_s0_003", "description": "Another evidenced step"},
        ],
        "narrative": "Some narrative without event references.",
    }
    result = check_unsupported_claims(llm_response)

    # 3 chain steps + 1 narrative = 4 total claims
    # 2 chain steps supported + 0 narrative (no evt_ in narrative) = 2 supported
    assert result["total_claims"] == 4
    assert result["unsupported_claims"] == 2
    assert result["supported_claims"] == 2
    assert result["evidence_grounding"] == 50.0


def test_unsupported_claims_fully_grounded():
    """All steps have event_ids and narrative references events -> 100% grounded."""
    llm_response = {
        "attack_chain": [
            {"step": 1, "event_id": "evt_s0_001", "description": "Step 1"},
        ],
        "narrative": "Based on evt_s0_001, the attack is confirmed.",
    }
    result = check_unsupported_claims(llm_response)

    assert result["total_claims"] == 2
    assert result["unsupported_claims"] == 0
    assert result["evidence_grounding"] == 100.0


# ── check_actor_references ───────────────────────────────────────────────────

def test_actor_not_in_events(sample_normalized_events):
    """Suspect 'user_99' not present in events should be flagged."""
    valid_events = {e["event_id"]: e for e in sample_normalized_events}
    llm_response = {"suspect": "user_99"}
    result = check_actor_references(llm_response, valid_events)

    assert result["suspect"] == "user_99"
    assert result["suspect_in_events"] is False


def test_actor_in_events(sample_normalized_events):
    """Suspect 'user_04' is present in events -> should not be flagged."""
    valid_events = {e["event_id"]: e for e in sample_normalized_events}
    llm_response = {"suspect": "user_04"}
    result = check_actor_references(llm_response, valid_events)

    assert result["suspect"] == "user_04"
    assert result["suspect_in_events"] is True
    assert "user_04" in result["actors_in_events"]
