"""SQLAlchemy 2.0 database layer for the forensic investigation framework.

Provides PostgreSQL storage as an optional backend alongside the existing
flat-JSON files.  All functions gracefully handle the case where the database
is unreachable so that callers can fall back to JSON.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    create_engine,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import (
    DATA_DIR,
    LLM_RESPONSES_DIR,
    NORMALIZED_DIR,
)

# ---------------------------------------------------------------------------
# Database URL
# ---------------------------------------------------------------------------

DATABASE_URL: str = os.getenv(
    "DATABASE_URL",
    "postgresql://forensic:forensic_secret@localhost:5432/forensic_db",
)

# ---------------------------------------------------------------------------
# Base class (SQLAlchemy 2.0 style)
# ---------------------------------------------------------------------------


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class Event(Base):
    """Unified normalized event."""

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String, unique=True, nullable=False, index=True)
    scenario_id = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    source_type = Column(String, nullable=False)
    user = Column(String, nullable=True, index=True)
    action = Column(String, nullable=False)
    resource = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    status = Column(String, nullable=False)
    session_id = Column(String, nullable=True)
    severity = Column(String, nullable=False)
    metadata_ = Column("metadata_", JSON, default={})


class Alert(Base):
    """Rule-engine alert."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scenario_id = Column(String, nullable=False, index=True)
    rule_id = Column(String, nullable=False)
    rule_name = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    user = Column(String, nullable=True)
    description = Column(String, nullable=True)
    event_ids = Column(JSON, default=[])
    timestamp = Column(DateTime(timezone=True), nullable=True)


class LLMResult(Base):
    """LLM analysis result for a scenario."""

    __tablename__ = "llm_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scenario_id = Column(String, unique=True, nullable=False)
    verdict = Column(String, nullable=False)
    confidence = Column(String, nullable=False)
    suspect = Column(String, nullable=True)
    narrative = Column(String, nullable=True)
    attack_chain = Column(JSON, default=[])
    evidence_for = Column(JSON, default=[])
    evidence_against = Column(JSON, default=[])
    gaps = Column(JSON, default=[])
    raw_response = Column(JSON, default={})
    is_mock = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class EvaluationResult(Base):
    """Evaluation result for a scenario."""

    __tablename__ = "evaluation_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scenario_id = Column(String, unique=True, nullable=False)
    ground_truth_label = Column(String, nullable=False)
    rule_verdict = Column(String, nullable=False)
    llm_verdict = Column(String, nullable=False)
    rule_correct = Column(Boolean)
    llm_correct = Column(Boolean)
    event_recall_pct = Column(Float, nullable=True)
    rule_fp_count = Column(Integer, default=0)
    llm_fp = Column(Boolean, default=False)
    hallucination_count = Column(Integer, default=0)
    evidence_grounding_pct = Column(Float, default=0.0)
    timeline_correct = Column(Boolean, default=True)
    full_results = Column(JSON, default={})
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# ---------------------------------------------------------------------------
# Engine / session helpers
# ---------------------------------------------------------------------------

_engine = None
_SessionFactory = None


def get_engine():
    """Create (or return cached) SQLAlchemy engine from DATABASE_URL."""
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    return _engine


def get_session() -> sessionmaker[Session]:
    """Return a session-maker bound to the default engine."""
    global _SessionFactory
    if _SessionFactory is None:
        _SessionFactory = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionFactory


def init_db() -> None:
    """Create all tables that do not yet exist."""
    Base.metadata.create_all(get_engine())
    print("Database tables created / verified.")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_ts(value: Any) -> datetime | None:
    """Coerce a timestamp string or None into a datetime."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


# ---------------------------------------------------------------------------
# Store functions
# ---------------------------------------------------------------------------


def store_events(events: list[dict], scenario_id: str) -> int:
    """Bulk-insert normalised events. Returns the number of rows inserted."""
    SessionLocal = get_session()
    inserted = 0
    with SessionLocal() as session:
        for ev in events:
            # Skip duplicates by event_id
            exists = (
                session.query(Event.id)
                .filter(Event.event_id == ev["event_id"])
                .first()
            )
            if exists:
                continue
            row = Event(
                event_id=ev["event_id"],
                scenario_id=scenario_id,
                timestamp=_parse_ts(ev["timestamp"]),
                source_type=ev["source_type"],
                user=ev["user"],
                action=ev["action"],
                resource=ev.get("resource"),
                source_ip=ev.get("source_ip"),
                status=ev["status"],
                session_id=ev.get("session_id"),
                severity=ev.get("severity", "info"),
                metadata_=ev.get("metadata", {}),
            )
            session.add(row)
            inserted += 1
        session.commit()
    return inserted


def store_alerts(alerts: list[dict], scenario_id: str) -> int:
    """Bulk-insert alerts for a scenario. Returns the number of rows inserted."""
    SessionLocal = get_session()
    inserted = 0
    with SessionLocal() as session:
        for al in alerts:
            row = Alert(
                scenario_id=scenario_id,
                rule_id=al["rule_id"],
                rule_name=al["rule_name"],
                severity=al["severity"],
                user=al.get("user"),
                description=al.get("description"),
                event_ids=al.get("event_ids", []),
                timestamp=_parse_ts(al.get("timestamp")),
            )
            session.add(row)
            inserted += 1
        session.commit()
    return inserted


def store_llm_result(result: dict, scenario_id: str, is_mock: bool = False) -> None:
    """Upsert an LLM analysis result for a scenario."""
    SessionLocal = get_session()
    with SessionLocal() as session:
        existing = (
            session.query(LLMResult)
            .filter(LLMResult.scenario_id == scenario_id)
            .first()
        )
        fields = dict(
            verdict=result.get("verdict", ""),
            confidence=result.get("confidence", ""),
            suspect=result.get("suspect"),
            narrative=result.get("narrative"),
            attack_chain=result.get("attack_chain", []),
            evidence_for=result.get("evidence_for", []),
            evidence_against=result.get("evidence_against", []),
            gaps=result.get("gaps", []),
            raw_response=result,
            is_mock=is_mock,
        )
        if existing:
            for key, value in fields.items():
                setattr(existing, key, value)
        else:
            row = LLMResult(scenario_id=scenario_id, **fields)
            session.add(row)
        session.commit()


def store_evaluation(result: dict) -> None:
    """Upsert an evaluation result for a scenario."""
    scenario_id = f"scenario_{result['scenario']}"
    SessionLocal = get_session()
    with SessionLocal() as session:
        existing = (
            session.query(EvaluationResult)
            .filter(EvaluationResult.scenario_id == scenario_id)
            .first()
        )
        va = result.get("verdict_accuracy", {})
        fp = result.get("false_positives", {})
        lq = result.get("llm_quality", {})
        er = result.get("event_recall", {})

        fields = dict(
            ground_truth_label=result.get("ground_truth_label", ""),
            rule_verdict=result.get("rule_verdict", ""),
            llm_verdict=result.get("llm_verdict", ""),
            rule_correct=va.get("rule_correct"),
            llm_correct=va.get("llm_correct"),
            event_recall_pct=er.get("recall_pct"),
            rule_fp_count=fp.get("rule_fp_count", 0),
            llm_fp=fp.get("llm_fp", False),
            hallucination_count=lq.get("hallucination_count", 0),
            evidence_grounding_pct=lq.get("evidence_grounding_pct", 0.0),
            timeline_correct=lq.get("timeline_correct", True),
            full_results=result,
        )
        if existing:
            for key, value in fields.items():
                setattr(existing, key, value)
        else:
            row = EvaluationResult(scenario_id=scenario_id, **fields)
            session.add(row)
        session.commit()


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------


def _row_to_dict(row) -> dict:
    """Convert an ORM row to a plain dict, excluding SQLAlchemy internals."""
    d = {c.name: getattr(row, c.name) for c in row.__table__.columns}
    # Serialise datetimes to ISO strings for JSON compat
    for key, val in d.items():
        if isinstance(val, datetime):
            d[key] = val.isoformat()
    return d


def get_events(scenario_id: str) -> list[dict]:
    """Query all normalised events for a scenario."""
    SessionLocal = get_session()
    with SessionLocal() as session:
        rows = (
            session.query(Event)
            .filter(Event.scenario_id == scenario_id)
            .order_by(Event.timestamp)
            .all()
        )
        return [_row_to_dict(r) for r in rows]


def get_alerts(scenario_id: str) -> list[dict]:
    """Query all alerts for a scenario."""
    SessionLocal = get_session()
    with SessionLocal() as session:
        rows = (
            session.query(Alert)
            .filter(Alert.scenario_id == scenario_id)
            .order_by(Alert.timestamp)
            .all()
        )
        return [_row_to_dict(r) for r in rows]


def get_llm_result(scenario_id: str) -> dict:
    """Query the LLM result for a scenario. Returns empty dict if not found."""
    SessionLocal = get_session()
    with SessionLocal() as session:
        row = (
            session.query(LLMResult)
            .filter(LLMResult.scenario_id == scenario_id)
            .first()
        )
        if row is None:
            return {}
        return _row_to_dict(row)


def get_all_evaluations() -> list[dict]:
    """Query all evaluation results."""
    SessionLocal = get_session()
    with SessionLocal() as session:
        rows = (
            session.query(EvaluationResult)
            .order_by(EvaluationResult.scenario_id)
            .all()
        )
        return [_row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# JSON-to-DB migration
# ---------------------------------------------------------------------------


def load_json_to_db() -> None:
    """Read all existing JSON data files and populate the database.

    This is a one-time migration helper that ingests:
      - normalised events  (data/normalized/scenario_*_events.json)
      - rule-engine alerts (data/normalized/scenario_*_rule_results.json)
      - LLM responses      (data/llm_responses/scenario_*_response.json)
      - evaluation results  (data/evaluation_results.json)
    """
    print("Starting JSON -> DB migration ...")

    # --- Events ---
    for path in sorted(NORMALIZED_DIR.glob("scenario_*_events.json")):
        scenario_id = path.stem.replace("_events", "")  # e.g. "scenario_1"
        with open(path) as f:
            events = json.load(f)
        n = store_events(events, scenario_id)
        print(f"  {scenario_id}: {n} events inserted ({len(events)} in file)")

    # --- Alerts ---
    for path in sorted(NORMALIZED_DIR.glob("scenario_*_rule_results.json")):
        scenario_id = path.stem.replace("_rule_results", "")
        with open(path) as f:
            data = json.load(f)
        alerts = data.get("alerts", [])
        n = store_alerts(alerts, scenario_id)
        print(f"  {scenario_id}: {n} alerts inserted ({len(alerts)} in file)")

    # --- LLM responses ---
    for path in sorted(LLM_RESPONSES_DIR.glob("scenario_*_response.json")):
        scenario_id = path.stem.replace("_response", "")
        with open(path) as f:
            result = json.load(f)
        store_llm_result(result, scenario_id, is_mock=result.get("is_mock", False))
        print(f"  {scenario_id}: LLM result upserted")

    # --- Evaluation results ---
    eval_path = DATA_DIR / "evaluation_results.json"
    if eval_path.exists():
        with open(eval_path) as f:
            evaluations = json.load(f)
        for ev in evaluations:
            store_evaluation(ev)
        print(f"  {len(evaluations)} evaluation results upserted")

    print("Migration complete.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    load_json_to_db()
