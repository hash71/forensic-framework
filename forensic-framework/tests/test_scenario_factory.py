"""Tests for the parameterized scenario generator.

These tests verify the four anti-designer-bias guarantees the paper relies
on: schema validity, label balance, determinism, and no leakage of
ground-truth fields into the events that the model is shown.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from app.ingestion.scenario_factory import (
    FAMILY_GENERATORS,
    build_generated_personas,
    generate_scenario,
    load_spec,
)


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SCENARIOS_DIR = DATA_DIR / "scenarios"
MANIFEST_PATH = DATA_DIR / "corpus_manifest.json"
BASELINES_PATH = DATA_DIR / "user_baselines.json"


REQUIRED_EVENT_FIELDS = {
    "event_id", "timestamp", "source_type", "user", "action",
    "resource", "source_ip", "status", "session_id", "severity", "metadata",
}

ALLOWED_SOURCE_TYPES = {
    "auth", "file_access", "admin", "network", "database",
    "web_server", "email",
}

ALLOWED_LABELS = {"BENIGN", "ATTACK"}


@pytest.fixture(scope="module")
def spec() -> dict:
    return load_spec()


@pytest.fixture(scope="module")
def generated_paths() -> list[Path]:
    """All scenario files with id >= 16 (the holdout)."""
    paths = []
    for path in sorted(SCENARIOS_DIR.glob("scenario_*.json")):
        # Extract the numeric id
        num = int(path.stem.split("_")[1])
        if num >= 16:
            paths.append(path)
    return paths


@pytest.fixture(scope="module")
def manifest() -> dict:
    with open(MANIFEST_PATH, "r") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def test_all_generated_scenarios_present(generated_paths):
    """One scenario file per holdout id (16-115 = 100 files)."""
    assert len(generated_paths) == 100, (
        f"Expected 100 holdout scenarios on disk; found {len(generated_paths)}"
    )


def test_scenario_schema_valid(generated_paths):
    """Every generated scenario has the canonical schema."""
    for path in generated_paths:
        with open(path, "r") as f:
            scen = json.load(f)
        assert set(scen.keys()) >= {
            "scenario_id", "name", "label", "description", "events",
        }, f"Missing top-level keys in {path.name}: {scen.keys()}"
        assert scen["label"] in ALLOWED_LABELS, (
            f"{path.name}: unexpected label {scen['label']!r}"
        )
        assert isinstance(scen["events"], list)
        assert len(scen["events"]) > 0, f"{path.name}: empty event list"


def test_event_schema_valid(generated_paths):
    """Every event in every generated scenario has the required fields."""
    for path in generated_paths:
        with open(path, "r") as f:
            scen = json.load(f)
        for evt in scen["events"]:
            assert REQUIRED_EVENT_FIELDS.issubset(evt.keys()), (
                f"{path.name} event {evt.get('event_id')}: missing fields "
                f"{REQUIRED_EVENT_FIELDS - evt.keys()}"
            )
            assert evt["source_type"] in ALLOWED_SOURCE_TYPES, (
                f"{path.name}: unknown source_type {evt['source_type']!r}"
            )
            # Timestamp parses
            datetime.fromisoformat(evt["timestamp"])


def test_event_ids_unique_within_scenario(generated_paths):
    """No duplicate event_ids inside a single scenario file."""
    for path in generated_paths:
        with open(path, "r") as f:
            scen = json.load(f)
        ids = [e["event_id"] for e in scen["events"]]
        assert len(ids) == len(set(ids)), (
            f"{path.name}: duplicate event_ids"
        )


# ---------------------------------------------------------------------------
# Label balance + corpus-level guarantees
# ---------------------------------------------------------------------------

def test_label_balance(generated_paths, spec):
    """The holdout must have >= 40 benign scenarios and a benign/attack mix
    that lets false-positive analysis be powered (the paper's headline FP
    metric needs sufficient benign volume)."""
    labels = []
    for path in generated_paths:
        with open(path, "r") as f:
            labels.append(json.load(f)["label"])
    counter = Counter(labels)
    assert counter["BENIGN"] >= 40, (
        f"Need >= 40 BENIGN holdout scenarios; have {counter['BENIGN']}"
    )
    assert counter["ATTACK"] >= 40, (
        f"Need >= 40 ATTACK holdout scenarios; have {counter['ATTACK']}"
    )


def test_hard_benign_count(manifest):
    """At least 15 scenarios must be 'hard_benign' (benign but alert-noisy).

    These are the scenarios that exercise FP behavior. The brief requires
    >= 15 so that false-positive rate has statistical traction.
    """
    hard_benign = [m for m in manifest["scenarios"] if m["hard_benign"]]
    assert len(hard_benign) >= 15, (
        f"Need >= 15 hard_benign holdouts; have {len(hard_benign)}"
    )


def test_manifest_matches_disk(generated_paths, manifest):
    """Each scenario on disk has exactly one matching manifest entry."""
    disk_ids = {p.stem for p in generated_paths}
    mf_ids = {m["scenario_id"] for m in manifest["scenarios"]}
    assert disk_ids == mf_ids, (
        f"Manifest/disk mismatch. Only on disk: {disk_ids - mf_ids}. "
        f"Only in manifest: {mf_ids - disk_ids}."
    )


def test_manifest_all_holdout(manifest):
    """Every entry in the generated manifest is flagged holdout=True."""
    for entry in manifest["scenarios"]:
        assert entry["holdout"] is True, (
            f"{entry['scenario_id']}: holdout flag must be True for "
            f"generator-created scenarios"
        )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------

def test_determinism_in_memory(spec):
    """Generating with the same seed must yield byte-identical event lists.

    This guards against accidental use of unseeded randomness (e.g. uuid,
    datetime.now, dict iteration order changes) inside the family generators.
    """
    existing = json.loads(BASELINES_PATH.read_text())
    combined = {**existing, **build_generated_personas(spec)}

    runs = []
    for _ in range(2):
        rng = random.Random(42)
        scen_rng = random.Random(rng.randint(0, 2**31 - 1))
        scen, gt, mf = generate_scenario(
            "credential_compromise", 16, scen_rng, combined, spec,
        )
        runs.append((scen, gt, mf))

    assert runs[0] == runs[1], (
        "Two identical seed runs produced different output — "
        "non-determinism in a family generator."
    )


# ---------------------------------------------------------------------------
# Leakage: ground-truth fields must not appear inside event payloads
# ---------------------------------------------------------------------------

_LEAKAGE_KEYS = {"attacker", "attack_steps", "ground_truth_label",
                  "label", "verdict", "is_attack"}


def test_no_ground_truth_leakage_into_events(generated_paths):
    """Event metadata must not contain ground-truth fields.

    The LLM is shown events as inputs. If the generator accidentally leaked
    a 'label' or 'attacker' key into an event payload, the model could
    classify by reading the answer key rather than the evidence.
    """
    for path in generated_paths:
        with open(path, "r") as f:
            scen = json.load(f)
        for evt in scen["events"]:
            md_keys = set(evt.get("metadata", {}).keys())
            leaked = _LEAKAGE_KEYS & md_keys
            assert not leaked, (
                f"{path.name} event {evt['event_id']}: ground-truth "
                f"leakage in metadata keys {leaked}"
            )
            # Also forbid keys starting with underscore that might hint
            # at hidden ground truth.
            underscore_keys = {k for k in evt.keys() if k.startswith("_")}
            assert not underscore_keys, (
                f"{path.name} event {evt['event_id']}: underscore-prefixed "
                f"fields {underscore_keys}"
            )


def test_personas_extended(spec):
    """user_baselines.json must contain >= 10 personas after generation."""
    baselines = json.loads(BASELINES_PATH.read_text())
    assert len(baselines) >= 10, (
        f"Expected >= 10 personas; have {len(baselines)}"
    )
    # The generator-created ones must all be present
    for uid in spec["personas"]["generated_ids"]:
        assert uid in baselines, f"Missing generated persona {uid}"


def test_all_users_resolvable(generated_paths):
    """Every event's `user` (if non-null) is a known persona in baselines.

    Prevents silent typos in generator code that would cause rules to skip
    scenarios because lookups fail. Rules like R001/R002/R005 require a
    matching baseline; an unknown user is a silent dead end.
    """
    baselines = json.loads(BASELINES_PATH.read_text())
    known = set(baselines.keys())
    for path in generated_paths:
        with open(path, "r") as f:
            scen = json.load(f)
        for evt in scen["events"]:
            user = evt.get("user")
            if user is None:
                continue
            assert user in known, (
                f"{path.name} event {evt['event_id']} references unknown "
                f"user {user!r}"
            )
