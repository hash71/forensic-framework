"""Resumable LLM experiment runner for the warrant benchmark."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import platform
import re
import traceback
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from app.evaluation.claims import InvestigationOutput, StrictModel, Verdict
from app.evaluation.warrant import (
    WARRANT_EVALUATOR_VERSION,
    WarrantAxis,
    WarrantLabel,
    apply_abstention_policy,
    assess_investigation,
    find_counterevidence,
)
from app.ingestion.warrant_benchmark import CASES_PATH, PROJECT_ROOT
from app.llm.warrant_client import (
    WarrantLLMClient,
    parse_json_object,
    prompt_fingerprint,
)
from app.llm.warrant_prompts import (
    GENERATOR_PROMPT_VERSION,
    GENERATOR_SYSTEM_PROMPT,
    SELF_REVIEW_PROMPT_VERSION,
    SELF_REVIEW_SYSTEM_PROMPT,
    VERIFIER_PROMPT_VERSION,
    VERIFIER_SYSTEM_PROMPT,
    build_warrant_generator_prompt,
    build_warrant_self_review_prompt,
    build_warrant_verifier_prompt,
)

RUN_SCHEMA_VERSION = "warrant-run-v1.0"


class VerifierClaim(StrictModel):
    claim_id: str
    overall_label: WarrantLabel
    axis_labels: dict[WarrantAxis, WarrantLabel]
    rationale: str
    missing_evidence: list[str] = Field(default_factory=list)


class VerifierOutput(StrictModel):
    claims: list[VerifierClaim]
    recommended_verdict: Verdict
    decisive_claim_ids_requiring_review: list[str] = Field(default_factory=list)
    omitted_counterevidence_event_ids: list[str] = Field(default_factory=list)
    verifier_confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def unique_claim_ids(self) -> VerifierOutput:
        claim_ids = [claim.claim_id for claim in self.claims]
        if len(claim_ids) != len(set(claim_ids)):
            raise ValueError("verifier claim_id values must be unique")
        return self


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_error(exc: Exception) -> dict[str, str]:
    def redact(value: str) -> str:
        value = re.sub(r"https?://[^\s'\"]+", "[REDACTED_ENDPOINT]", value)
        value = re.sub(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
        return value

    return {
        "type": type(exc).__name__,
        "message": redact(str(exc))[:1000],
        "traceback_tail": redact("\n".join(traceback.format_exception(exc)[-3:]))[-2000:],
    }


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


async def _git_commit() -> str | None:
    try:
        process = await asyncio.create_subprocess_exec(
            "git",
            "rev-parse",
            "HEAD",
            cwd=PROJECT_ROOT,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await process.communicate()
    except OSError:
        return None
    return stdout.decode().strip() if process.returncode == 0 else None


def _call_metadata(result: Any, raw_path: Path) -> dict[str, Any]:
    """Keep provenance fields in JSONL while storing model text only once."""

    values = asdict(result)
    values.pop("content", None)
    values.pop("response_json", None)
    try:
        artifact_path = raw_path.relative_to(PROJECT_ROOT)
    except ValueError:
        artifact_path = raw_path
    values["raw_response_path"] = str(artifact_path)
    values["raw_response_sha256"] = _sha256_text(result.content)
    values["estimated_cost_usd"] = None
    return values


def _run_key(case_id: str, condition: str, repetition: int) -> str:
    return f"{case_id}|{condition}|{repetition}"


def _load_completed(records_path: Path) -> set[str]:
    if not records_path.exists():
        return set()
    completed = set()
    with records_path.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            completed.add(_run_key(record["case_id"], record["condition"], record["repetition"]))
    return completed


def _raw_path(run_dir: Path, case_id: str, condition: str, repetition: int, stage: str) -> Path:
    safe = hashlib.sha256(f"{case_id}|{condition}|{repetition}|{stage}".encode()).hexdigest()[:12]
    return run_dir / "raw" / f"{case_id}__{condition}__r{repetition}__{stage}__{safe}.txt"


async def _call_generator(
    client: WarrantLLMClient,
    case: dict[str, Any],
    *,
    alerts_visible: bool,
    repetition: int,
    temperature: float,
    max_tokens: int,
    run_dir: Path,
    condition: str,
) -> tuple[dict[str, Any], InvestigationOutput | None]:
    prompt = build_warrant_generator_prompt(
        case_id=case["case_id"],
        baselines=case["baselines"],
        events=case["events"],
        alerts=case["alerts"] if alerts_visible else None,
    )
    metadata: dict[str, Any] = {
        "prompt_version": GENERATOR_PROMPT_VERSION,
        "prompt_sha256": prompt_fingerprint(GENERATOR_SYSTEM_PROMPT, prompt),
        "parser_status": "not_called",
    }
    try:
        result = await client.call(
            system_prompt=GENERATOR_SYSTEM_PROMPT,
            user_prompt=prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            seed=repetition,
        )
        raw_path = _raw_path(run_dir, case["case_id"], condition, repetition, "generator")
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(result.content)
        metadata["call"] = _call_metadata(result, raw_path)
        parsed = parse_json_object(result.content)
        output = InvestigationOutput.model_validate(parsed)
        metadata["parser_status"] = "valid"
        metadata["parsed_output"] = output.model_dump(mode="json")
        return metadata, output
    except Exception as exc:  # noqa: BLE001 - every endpoint/parser failure is retained.
        metadata["parser_status"] = "error"
        metadata["error"] = _safe_error(exc)
        return metadata, None


async def _call_verifier(
    client: WarrantLLMClient,
    case: dict[str, Any],
    output: InvestigationOutput,
    *,
    repetition: int,
    temperature: float,
    max_tokens: int,
    run_dir: Path,
    condition: str,
    verifier_model: str | None,
    self_review: bool = False,
) -> tuple[dict[str, Any], VerifierOutput | None]:
    if self_review:
        prompt = build_warrant_self_review_prompt(
            case_id=case["case_id"],
            baselines=case["baselines"],
            events=case["events"],
            alerts=case["alerts"],
            generator_output=output.model_dump(mode="json"),
        )
        system_prompt = SELF_REVIEW_SYSTEM_PROMPT
        prompt_version = SELF_REVIEW_PROMPT_VERSION
        stage = "self_review"
        review_model = client.model
    else:
        prompt = build_warrant_verifier_prompt(
            case_id=case["case_id"],
            events=case["events"],
            generator_output=output.model_dump(mode="json"),
        )
        system_prompt = VERIFIER_SYSTEM_PROMPT
        prompt_version = VERIFIER_PROMPT_VERSION
        stage = "verifier"
        review_model = verifier_model or client.model
    metadata: dict[str, Any] = {
        "prompt_version": prompt_version,
        "prompt_sha256": prompt_fingerprint(system_prompt, prompt),
        "parser_status": "not_called",
        "review_mode": "same_model_self_review" if self_review else "alert_blind_verifier",
    }
    try:
        result = await client.call(
            system_prompt=system_prompt,
            user_prompt=prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            seed=100_000 + repetition,
            model=review_model,
        )
        raw_path = _raw_path(run_dir, case["case_id"], condition, repetition, stage)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(result.content)
        metadata["call"] = _call_metadata(result, raw_path)
        parsed = parse_json_object(result.content)
        review = VerifierOutput.model_validate(parsed)
        expected_claim_ids = {claim.claim_id for claim in output.claims}
        reviewed_claim_ids = {claim.claim_id for claim in review.claims}
        if reviewed_claim_ids != expected_claim_ids:
            raise ValueError("review must return each generator claim exactly once")
        if review.recommended_verdict not in {output.verdict, Verdict.INSUFFICIENT}:
            raise ValueError("review may preserve the verdict or abstain, but may not reverse it")
        metadata["parser_status"] = "valid"
        metadata["parsed_output"] = review.model_dump(mode="json")
        return metadata, review
    except Exception as exc:  # noqa: BLE001 - every endpoint/parser failure is retained.
        metadata["parser_status"] = "error"
        metadata["error"] = _safe_error(exc)
        return metadata, None


def _base_record(
    case: dict[str, Any],
    *,
    run_id: str,
    condition: str,
    repetition: int,
    model_id: str,
) -> dict[str, Any]:
    return {
        "run_schema_version": RUN_SCHEMA_VERSION,
        "warrant_evaluator_version": WARRANT_EVALUATOR_VERSION,
        "run_id": run_id,
        "recorded_at": _utc_now(),
        "case_id": case["case_id"],
        "base_case_id": case["base_case_id"],
        "family": case["family"],
        "split": case["split"],
        "variant": case["variant"],
        "condition": condition,
        "repetition": repetition,
        "requested_model": model_id,
        "expected_verdict": case["ground_truth"]["warranted_verdict"],
        "expected_suspect": case["ground_truth"]["warranted_suspect"],
    }


async def run_case_condition(
    client: WarrantLLMClient,
    case: dict[str, Any],
    *,
    run_id: str,
    condition: str,
    repetition: int,
    temperature: float,
    max_tokens: int,
    run_dir: Path,
    verifier_model: str | None = None,
) -> dict[str, Any]:
    record = _base_record(
        case,
        run_id=run_id,
        condition=condition,
        repetition=repetition,
        model_id=client.model,
    )
    alerts_visible = condition != "llm_events_only"
    generator, output = await _call_generator(
        client,
        case,
        alerts_visible=alerts_visible,
        repetition=repetition,
        temperature=temperature,
        max_tokens=max_tokens,
        run_dir=run_dir,
        condition=condition,
    )
    record["generator"] = generator
    if output is None:
        record.update({
            "operational_status": "generator_failure",
            "predicted_verdict": None,
            "predicted_suspect": None,
            "verdict_correct": False,
            "suspect_correct": False,
            "exact_correct": False,
            "verifier": None,
            "mechanical_warrant": None,
            "mechanical_counterevidence": None,
            "mechanical_review": None,
        })
        return record

    warrant = assess_investigation(output, case["events"], case["baselines"])
    counter = find_counterevidence(output, case["events"], case["baselines"])
    review = apply_abstention_policy(output, warrant, counter)
    record["mechanical_warrant"] = warrant.model_dump(mode="json")
    record["mechanical_counterevidence"] = counter.model_dump(mode="json")
    record["mechanical_review"] = review.model_dump(mode="json")

    verifier_data: dict[str, Any] | None = None
    verifier_output: VerifierOutput | None = None
    if condition in {"llm_self_review", "generator_verifier", "generator_verifier_abstention"}:
        verifier_data, verifier_output = await _call_verifier(
            client,
            case,
            output,
            repetition=repetition,
            temperature=temperature,
            max_tokens=max_tokens,
            run_dir=run_dir,
            condition=condition,
            verifier_model=verifier_model,
            self_review=condition == "llm_self_review",
        )
    record["verifier"] = verifier_data

    predicted_verdict = output.verdict
    predicted_suspect = output.suspect
    operational_status = "valid"
    if condition in {"llm_self_review", "generator_verifier", "generator_verifier_abstention"}:
        if verifier_output is None:
            operational_status = "review_failure"
        elif verifier_output.recommended_verdict == Verdict.INSUFFICIENT:
            predicted_verdict = Verdict.INSUFFICIENT
            predicted_suspect = None
            operational_status = "valid_abstained"
    if (
        condition == "generator_verifier_abstention"
        and review.reviewed_verdict == Verdict.INSUFFICIENT
    ):
        predicted_verdict = Verdict.INSUFFICIENT
        predicted_suspect = None
        operational_status = "valid_abstained"

    evaluable = operational_status.startswith("valid")
    verdict_correct = evaluable and predicted_verdict.value == record["expected_verdict"]
    suspect_correct = evaluable and predicted_suspect == record["expected_suspect"]

    record.update({
        "operational_status": operational_status,
        "predicted_verdict": predicted_verdict.value,
        "predicted_suspect": predicted_suspect,
        "verdict_correct": verdict_correct,
        "suspect_correct": suspect_correct,
        "exact_correct": verdict_correct and suspect_correct,
    })
    return record


async def run_experiment(
    cases: list[dict[str, Any]],
    *,
    run_id: str,
    conditions: list[str],
    repetitions: int,
    concurrency: int,
    temperature: float,
    max_tokens: int,
    run_dir: Path,
    resume: bool = True,
    generator_model: str | None = None,
    verifier_model: str | None = None,
    provider: str | None = None,
    model_revision: str | None = None,
) -> dict[str, Any]:
    run_dir.mkdir(parents=True, exist_ok=True)
    records_path = run_dir / "records.jsonl"
    completed = _load_completed(records_path) if resume else set()
    work = [
        (case, condition, repetition)
        for case in cases
        for condition in conditions
        for repetition in range(repetitions)
        if _run_key(case["case_id"], condition, repetition) not in completed
    ]
    semaphore = asyncio.Semaphore(max(1, concurrency))
    write_lock = asyncio.Lock()
    counts = {"planned": len(work), "completed": 0, "valid": 0, "failures": 0}

    async with WarrantLLMClient(
        model=generator_model,
        provider=provider,
        model_revision=model_revision,
    ) as client:
        async def execute(item: tuple[dict[str, Any], str, int]) -> None:
            case, condition, repetition = item
            async with semaphore:
                record = await run_case_condition(
                    client,
                    case,
                    run_id=run_id,
                    condition=condition,
                    repetition=repetition,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    run_dir=run_dir,
                    verifier_model=verifier_model,
                )
            line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
            async with write_lock:
                with records_path.open("a") as handle:
                    handle.write(line)
                counts["completed"] += 1
                if record["operational_status"].startswith("valid"):
                    counts["valid"] += 1
                else:
                    counts["failures"] += 1

        await asyncio.gather(*(execute(item) for item in work))

    case_ids = sorted(case["case_id"] for case in cases)
    git_commit = await _git_commit()
    dependency_versions = {}
    for package in ("httpx", "pydantic"):
        try:
            dependency_versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            dependency_versions[package] = None
    manifest = {
        "run_schema_version": RUN_SCHEMA_VERSION,
        "warrant_evaluator_version": WARRANT_EVALUATOR_VERSION,
        "run_id": run_id,
        "created_at": _utc_now(),
        "conditions": conditions,
        "repetitions": repetitions,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "case_count": len(cases),
        "base_case_count": len({case["base_case_id"] for case in cases}),
        "case_ids_sha256": _sha256_text("\n".join(case_ids)),
        "benchmark_sha256": hashlib.sha256(CASES_PATH.read_bytes()).hexdigest(),
        "requested_generator_model": client.model,
        "requested_verifier_model": verifier_model or client.model,
        "provider": client.provider,
        "model_revision": client.model_revision,
        "endpoint_sha256": hashlib.sha256(client.endpoint.encode()).hexdigest(),
        "git_commit": git_commit,
        "python_version": platform.python_version(),
        "dependency_versions": dependency_versions,
        "records_path": str(records_path.relative_to(PROJECT_ROOT)),
        "counts_for_this_invocation": counts,
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest
