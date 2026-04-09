"""FastAPI backend for the Forensic Investigation Framework."""

from __future__ import annotations

import json
import traceback
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.config import (
    DATA_DIR,
    GROUND_TRUTH_DIR,
    LLM_RESPONSES_DIR,
    NORMALIZED_DIR,
    SCENARIOS_DIR,
)

# ---------------------------------------------------------------------------
# Path constants
# ---------------------------------------------------------------------------

REPORTS_DIR = DATA_DIR / "reports"
BASELINES_PATH = DATA_DIR / "user_baselines.json"
GROUND_TRUTH_PATH = GROUND_TRUTH_DIR / "ground_truth.json"
EVALUATION_PATH = DATA_DIR / "evaluation_results.json"

def _discover_scenario_ids() -> set[int]:
    """Scan data/scenarios/scenario_*.json and return the set of scenario numbers."""
    scenario_files = sorted((DATA_DIR / "scenarios").glob("scenario_*.json"))
    return {int(f.stem.split("_")[1]) for f in scenario_files}

VALID_SCENARIO_IDS = _discover_scenario_ids() or {1, 2, 3, 4}

# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class HealthResponse(BaseModel):
    status: str = "ok"
    service: str = "forensic-framework"


class ScenarioSummary(BaseModel):
    scenario_id: str
    name: str
    label: str
    description: str | None = None


class ScenariosListResponse(BaseModel):
    scenarios: list[ScenarioSummary]


class EventItem(BaseModel):
    event_id: str
    timestamp: str
    source_type: str
    user: str
    action: str
    resource: str | None = None
    source_ip: str | None = None
    status: str
    session_id: str | None = None
    severity: str = "info"
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventsResponse(BaseModel):
    scenario_id: str
    count: int
    events: list[dict[str, Any]]


class TimelineResponse(BaseModel):
    scenario_id: str
    timeline: list[dict[str, Any]] | dict[str, Any]


class RuleResultsResponse(BaseModel):
    scenario_id: str
    verdict: str
    alert_count: int
    rules_triggered: list[str]
    severity_summary: dict[str, int]
    alerts: list[dict[str, Any]]


class LLMResultResponse(BaseModel):
    scenario_id: str
    result: dict[str, Any]


class EvaluationResponse(BaseModel):
    evaluations: list[dict[str, Any]]


class ScenarioEvaluationResponse(BaseModel):
    scenario_id: str
    evaluation: dict[str, Any]


class ReportResponse(BaseModel):
    scenario_id: str
    report: dict[str, Any]


class ScenarioDetailResponse(BaseModel):
    scenario_id: str
    scenario_info: dict[str, Any]
    events: list[dict[str, Any]]
    timeline: list[dict[str, Any]] | dict[str, Any] | None = None
    rule_results: dict[str, Any] | None = None
    llm_results: dict[str, Any] | None = None
    evaluation: dict[str, Any] | None = None


class PipelineRequest(BaseModel):
    use_mock: bool = True


class PipelineResponse(BaseModel):
    status: str
    steps_completed: list[str]
    summary: dict[str, Any]
    errors: list[str] = Field(default_factory=list)


class LLMAnalyzeRequest(BaseModel):
    use_mock: bool = False


class LLMAnalyzeResponse(BaseModel):
    scenario_id: str
    result: dict[str, Any]


class BaselinesResponse(BaseModel):
    baselines: dict[str, Any]


class GroundTruthResponse(BaseModel):
    scenarios: list[dict[str, Any]]


# ---------------------------------------------------------------------------
# JSON file helpers
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any | None:
    """Load a JSON file, returning None if it does not exist."""
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _validate_scenario_id(scenario_id: int) -> None:
    """Raise 404 if scenario_id is not in 1..4."""
    if scenario_id not in VALID_SCENARIO_IDS:
        raise HTTPException(
            status_code=404,
            detail=f"Scenario {scenario_id} not found. Valid IDs: {sorted(VALID_SCENARIO_IDS)}.",
        )


def _load_scenario_events(scenario_id: int) -> list[dict]:
    """Load normalized events for a scenario from JSON."""
    path = NORMALIZED_DIR / f"scenario_{scenario_id}_events.json"
    data = _load_json(path)
    if data is None:
        return []
    return data


def _load_timeline(scenario_id: int) -> Any | None:
    """Load timeline data for a scenario."""
    path = NORMALIZED_DIR / f"scenario_{scenario_id}_timeline.json"
    return _load_json(path)


def _load_rule_results(scenario_id: int) -> dict | None:
    """Load rule engine results for a scenario."""
    path = NORMALIZED_DIR / f"scenario_{scenario_id}_rule_results.json"
    return _load_json(path)


def _load_llm_results(scenario_id: int) -> dict | None:
    """Load LLM analysis results for a scenario."""
    path = LLM_RESPONSES_DIR / f"scenario_{scenario_id}_response.json"
    return _load_json(path)


def _load_evaluation_results() -> list[dict]:
    """Load evaluation results for all scenarios."""
    data = _load_json(EVALUATION_PATH)
    if data is None:
        return []
    return data


def _load_ground_truth() -> list[dict]:
    """Load ground truth data."""
    data = _load_json(GROUND_TRUTH_PATH)
    if data is None:
        return []
    return data.get("scenarios", [])


def _load_baselines() -> dict:
    """Load user baselines."""
    data = _load_json(BASELINES_PATH)
    if data is None:
        return {}
    return data


def _load_scenario_info(scenario_id: int) -> dict | None:
    """Load scenario definition file."""
    path = SCENARIOS_DIR / f"scenario_{scenario_id}.json"
    return _load_json(path)


def _load_report(scenario_id: int) -> dict | None:
    """Load a generated forensic report for a scenario."""
    path = REPORTS_DIR / f"scenario_{scenario_id}_report.json"
    return _load_json(path)


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Forensic Investigation Framework",
    description="API for forensic log analysis with rule-based and LLM-assisted detection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event() -> None:
    """Initialize database on startup (best-effort)."""
    try:
        from app.database import init_db

        init_db()
    except Exception as exc:
        print(f"[WARNING] Database initialization failed (non-fatal): {exc}")


# ---------------------------------------------------------------------------
# 1. Health check
# ---------------------------------------------------------------------------


@app.get("/", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse()


# ---------------------------------------------------------------------------
# 2. List all scenarios
# ---------------------------------------------------------------------------


@app.get("/api/scenarios", response_model=ScenariosListResponse)
async def list_scenarios() -> ScenariosListResponse:
    """List all scenarios with ground truth labels and basic info."""
    ground_truths = _load_ground_truth()
    scenarios: list[ScenarioSummary] = []

    for gt in ground_truths:
        sid = gt.get("id", "")
        scenario_num = int(sid.split("_")[1]) if "_" in sid else 0
        scenario_info = _load_scenario_info(scenario_num)
        description = (
            scenario_info.get("description") if scenario_info else None
        )

        scenarios.append(
            ScenarioSummary(
                scenario_id=sid,
                name=gt.get("name", ""),
                label=gt.get("label", ""),
                description=description,
            )
        )

    return ScenariosListResponse(scenarios=scenarios)


# ---------------------------------------------------------------------------
# 3. Get full scenario detail
# ---------------------------------------------------------------------------


@app.get("/api/scenarios/{scenario_id}", response_model=ScenarioDetailResponse)
async def get_scenario_detail(scenario_id: int) -> ScenarioDetailResponse:
    """Get full detail for a scenario: events, timeline, rules, LLM, evaluation."""
    _validate_scenario_id(scenario_id)

    scenario_info = _load_scenario_info(scenario_id) or {}
    events = _load_scenario_events(scenario_id)
    timeline = _load_timeline(scenario_id)
    rule_results = _load_rule_results(scenario_id)
    llm_results = _load_llm_results(scenario_id)

    # Find evaluation for this scenario
    all_evals = _load_evaluation_results()
    evaluation = None
    for ev in all_evals:
        if ev.get("scenario") == scenario_id:
            evaluation = ev
            break

    return ScenarioDetailResponse(
        scenario_id=f"scenario_{scenario_id}",
        scenario_info=scenario_info,
        events=events,
        timeline=timeline,
        rule_results=rule_results,
        llm_results=llm_results,
        evaluation=evaluation,
    )


# ---------------------------------------------------------------------------
# 4. Get events for a scenario (with optional filters)
# ---------------------------------------------------------------------------


@app.get("/api/events/{scenario_id}", response_model=EventsResponse)
async def get_events(
    scenario_id: int,
    source_type: Optional[str] = Query(None, description="Filter by source_type"),
    action: Optional[str] = Query(None, description="Filter by action"),
    user: Optional[str] = Query(None, description="Filter by user"),
) -> EventsResponse:
    """Get all normalized events for a scenario, with optional filters."""
    _validate_scenario_id(scenario_id)

    events = _load_scenario_events(scenario_id)

    if source_type:
        events = [e for e in events if e.get("source_type") == source_type]
    if action:
        events = [e for e in events if e.get("action") == action]
    if user:
        events = [e for e in events if e.get("user") == user]

    return EventsResponse(
        scenario_id=f"scenario_{scenario_id}",
        count=len(events),
        events=events,
    )


# ---------------------------------------------------------------------------
# 5. Get timeline for a scenario
# ---------------------------------------------------------------------------


@app.get("/api/timeline/{scenario_id}", response_model=TimelineResponse)
async def get_timeline(scenario_id: int) -> TimelineResponse:
    """Get timeline data for a scenario."""
    _validate_scenario_id(scenario_id)

    timeline = _load_timeline(scenario_id)
    if timeline is None:
        raise HTTPException(
            status_code=404,
            detail=f"Timeline data not found for scenario {scenario_id}.",
        )

    return TimelineResponse(
        scenario_id=f"scenario_{scenario_id}",
        timeline=timeline,
    )


# ---------------------------------------------------------------------------
# 6. Get rule engine results for a scenario
# ---------------------------------------------------------------------------


@app.get("/api/rules/{scenario_id}", response_model=RuleResultsResponse)
async def get_rule_results(scenario_id: int) -> RuleResultsResponse:
    """Get rule engine results for a scenario."""
    _validate_scenario_id(scenario_id)

    results = _load_rule_results(scenario_id)
    if results is None:
        raise HTTPException(
            status_code=404,
            detail=f"Rule results not found for scenario {scenario_id}.",
        )

    return RuleResultsResponse(
        scenario_id=f"scenario_{scenario_id}",
        verdict=results.get("verdict", ""),
        alert_count=results.get("alert_count", 0),
        rules_triggered=results.get("rules_triggered", []),
        severity_summary=results.get("severity_summary", {}),
        alerts=results.get("alerts", []),
    )


# ---------------------------------------------------------------------------
# 7. Get LLM analysis results for a scenario
# ---------------------------------------------------------------------------


@app.get("/api/llm/{scenario_id}", response_model=LLMResultResponse)
async def get_llm_results(scenario_id: int) -> LLMResultResponse:
    """Get LLM analysis results for a scenario."""
    _validate_scenario_id(scenario_id)

    results = _load_llm_results(scenario_id)
    if results is None:
        raise HTTPException(
            status_code=404,
            detail=f"LLM results not found for scenario {scenario_id}.",
        )

    return LLMResultResponse(
        scenario_id=f"scenario_{scenario_id}",
        result=results,
    )


# ---------------------------------------------------------------------------
# 8. Get evaluation results for all scenarios
# ---------------------------------------------------------------------------


@app.get("/api/evaluation", response_model=EvaluationResponse)
async def get_all_evaluations() -> EvaluationResponse:
    """Get evaluation results for all scenarios (the comparison table)."""
    evaluations = _load_evaluation_results()
    return EvaluationResponse(evaluations=evaluations)


# ---------------------------------------------------------------------------
# 9. Get evaluation for a specific scenario
# ---------------------------------------------------------------------------


@app.get(
    "/api/evaluation/{scenario_id}", response_model=ScenarioEvaluationResponse
)
async def get_scenario_evaluation(
    scenario_id: int,
) -> ScenarioEvaluationResponse:
    """Get evaluation for a specific scenario."""
    _validate_scenario_id(scenario_id)

    all_evals = _load_evaluation_results()
    for ev in all_evals:
        if ev.get("scenario") == scenario_id:
            return ScenarioEvaluationResponse(
                scenario_id=f"scenario_{scenario_id}",
                evaluation=ev,
            )

    raise HTTPException(
        status_code=404,
        detail=f"Evaluation not found for scenario {scenario_id}.",
    )


# ---------------------------------------------------------------------------
# 10. Get forensic report for a scenario
# ---------------------------------------------------------------------------


@app.get("/api/reports/{scenario_id}", response_model=ReportResponse)
async def get_report(scenario_id: int) -> ReportResponse:
    """Get the forensic report for a scenario."""
    _validate_scenario_id(scenario_id)

    report = _load_report(scenario_id)
    if report is None:
        raise HTTPException(
            status_code=404,
            detail=f"Report not found for scenario {scenario_id}. Run the pipeline first.",
        )

    return ReportResponse(
        scenario_id=f"scenario_{scenario_id}",
        report=report,
    )


# ---------------------------------------------------------------------------
# 11. Run full pipeline
# ---------------------------------------------------------------------------


@app.post("/api/pipeline/run", response_model=PipelineResponse)
async def run_pipeline(request: PipelineRequest) -> PipelineResponse:
    """Run the full forensic analysis pipeline."""
    steps_completed: list[str] = []
    errors: list[str] = []
    summary: dict[str, Any] = {}

    try:
        # Step 1: Generate logs
        from app.ingestion.log_generator import generate_all as generate_logs

        generate_logs()
        steps_completed.append("log_generation")
    except Exception as exc:
        errors.append(f"log_generation: {exc}")

    try:
        # Step 2: Parse logs
        from app.ingestion.parser import parse_all_scenarios

        parsed = parse_all_scenarios()
        steps_completed.append("parsing")
    except Exception as exc:
        errors.append(f"parsing: {exc}")
        parsed = {}

    try:
        # Step 3: Normalize events
        from app.normalizer.normalizer import normalize_all

        normalized = normalize_all(parsed)
        steps_completed.append("normalization")
    except Exception as exc:
        errors.append(f"normalization: {exc}")

    try:
        # Step 4: Build timelines
        from app.timeline.timeline import build_all_timelines

        timelines = build_all_timelines()
        steps_completed.append("timeline_building")
    except Exception as exc:
        errors.append(f"timeline_building: {exc}")

    try:
        # Step 5: Run correlations
        from app.correlation.correlator import correlate_all

        correlations = correlate_all()
        steps_completed.append("correlation")
    except Exception as exc:
        errors.append(f"correlation: {exc}")

    try:
        # Step 6: Run rule engine
        from app.rules.rule_engine import evaluate_all as rule_evaluate_all

        rule_results = rule_evaluate_all()
        steps_completed.append("rule_engine")
        summary["rule_verdicts"] = {
            k: v.get("verdict", "") for k, v in rule_results.items()
        }
    except Exception as exc:
        errors.append(f"rule_engine: {exc}")

    try:
        # Step 7: Run LLM analysis
        from app.llm.client import analyze_all

        llm_results = await analyze_all(use_mock=request.use_mock)
        steps_completed.append("llm_analysis")
        summary["llm_verdicts"] = {
            f"scenario_{k}": v.get("verdict", "")
            for k, v in llm_results.items()
        }
        summary["llm_mode"] = "mock" if request.use_mock else "live"
    except Exception as exc:
        errors.append(f"llm_analysis: {exc}")

    try:
        # Step 8: Run hallucination checks
        from app.llm.hallucination_checker import run_hallucination_check

        hallucination_results = {}
        for scenario_num in sorted(VALID_SCENARIO_IDS):
            llm_resp = _load_llm_results(scenario_num)
            if llm_resp:
                hallucination_results[scenario_num] = run_hallucination_check(
                    llm_resp, scenario_num
                )
        steps_completed.append("hallucination_checks")
        summary["hallucination_counts"] = {
            f"scenario_{k}": v.get("hallucination_count", 0)
            for k, v in hallucination_results.items()
        }
    except Exception as exc:
        errors.append(f"hallucination_checks: {exc}")

    try:
        # Step 9: Run evaluation
        from app.evaluation.evaluator import evaluate_all as eval_evaluate_all

        eval_results = eval_evaluate_all()
        steps_completed.append("evaluation")
        summary["evaluation_count"] = len(eval_results)
    except Exception as exc:
        errors.append(f"evaluation: {exc}")

    try:
        # Step 10: Generate reports
        from app.reporting.reporter import generate_all_reports

        reports = generate_all_reports()
        steps_completed.append("report_generation")
        summary["reports_generated"] = len(reports)
    except Exception as exc:
        errors.append(f"report_generation: {exc}")

    try:
        # Step 11: Store everything in DB
        from app.database import (
            load_json_to_db,
            store_alerts,
            store_events,
            store_llm_result,
            store_evaluation,
        )

        load_json_to_db()
        steps_completed.append("database_storage")
    except Exception as exc:
        errors.append(f"database_storage: {exc}")

    summary["total_steps"] = len(steps_completed)
    summary["total_errors"] = len(errors)

    status = "completed" if not errors else "completed_with_errors"

    return PipelineResponse(
        status=status,
        steps_completed=steps_completed,
        summary=summary,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# 12. Run LLM analysis for a single scenario
# ---------------------------------------------------------------------------


@app.post(
    "/api/llm/analyze/{scenario_id}", response_model=LLMAnalyzeResponse
)
async def analyze_scenario(
    scenario_id: int, request: LLMAnalyzeRequest
) -> LLMAnalyzeResponse:
    """Run LLM analysis for a single scenario (async)."""
    _validate_scenario_id(scenario_id)

    try:
        from app.llm.client import analyze_scenario as llm_analyze_scenario

        result = await llm_analyze_scenario(
            scenario_id, use_mock=request.use_mock
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"LLM analysis failed for scenario {scenario_id}: {exc}",
        )

    return LLMAnalyzeResponse(
        scenario_id=f"scenario_{scenario_id}",
        result=result,
    )


# ---------------------------------------------------------------------------
# 13. Get user baselines
# ---------------------------------------------------------------------------


@app.get("/api/baselines", response_model=BaselinesResponse)
async def get_baselines() -> BaselinesResponse:
    """Get user baselines."""
    baselines = _load_baselines()
    return BaselinesResponse(baselines=baselines)


# ---------------------------------------------------------------------------
# 14. Get ground truth data
# ---------------------------------------------------------------------------


@app.get("/api/ground-truth", response_model=GroundTruthResponse)
async def get_ground_truth() -> GroundTruthResponse:
    """Get ground truth data for all scenarios."""
    scenarios = _load_ground_truth()
    return GroundTruthResponse(scenarios=scenarios)
