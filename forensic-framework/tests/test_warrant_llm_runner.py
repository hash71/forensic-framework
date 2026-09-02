"""Tests for strict parsing and provenance-preserving LLM experiment runs."""

from __future__ import annotations

import asyncio
import copy
import json
from pathlib import Path

import httpx
import pytest

from app.evaluation.warrant_results import summarize_run, verify_artifacts
from app.llm.warrant_client import (
    ChatCompletionResult,
    WarrantLLMClient,
    parse_json_object,
)
from app.llm.warrant_runner import (
    _load_completed,
    _safe_error,
    run_case_condition,
    run_case_group,
)


def _case() -> dict:
    return {
        "case_id": "case_runner_001__canonical",
        "base_case_id": "case_runner_001",
        "family": "credential_compromise",
        "split": "development",
        "variant": "canonical",
        "baselines": {"user_07": {"normal_ips": ["10.0.0.7"]}},
        "alerts": [{"alert_id": "alert_1", "actor": "user_07", "severity": "high"}],
        "events": [
            {
                "event_id": "evt_001",
                "timestamp": "2026-09-01T02:00:00+06:00",
                "source_type": "auth",
                "user": "user_07",
                "action": "login",
                "resource": "cloud_console",
                "source_ip": "203.0.113.7",
                "status": "success",
                "session_id": "session_1",
                "metadata": {"authorized": False},
            }
        ],
        "ground_truth": {
            "warranted_verdict": "YES",
            "warranted_suspect": "user_07",
        },
    }


def _investigation() -> dict:
    return {
        "schema_version": "forensic-claim-v2.0",
        "case_id": "case_runner_001__canonical",
        "verdict": "YES",
        "suspect": "user_07",
        "claims": [
            {
                "claim_id": "c1",
                "claim_type": "observation",
                "subject": "user_07",
                "predicate": "login",
                "object": "cloud_console",
                "time": "2026-09-01T02:00:00+06:00",
                "quantity": None,
                "scope": None,
                "modality": "observed",
                "authorization": "unauthorized",
                "intent": None,
                "causal_parent_claim_ids": [],
                "cited_event_ids": ["evt_001"],
                "evidence_relation": "supports",
                "confidence": 0.95,
                "decisive": True,
                "rationale": "The event explicitly records an unauthorized successful login.",
            },
            {
                "claim_id": "decision_1",
                "claim_type": "decision",
                "subject": "user_07",
                "predicate": "verdict_yes",
                "object": "security_incident",
                "time": None,
                "quantity": None,
                "scope": None,
                "modality": "probable",
                "authorization": None,
                "intent": None,
                "causal_parent_claim_ids": ["c1"],
                "cited_event_ids": ["evt_001"],
                "evidence_relation": "supports",
                "confidence": 0.90,
                "decisive": True,
                "rationale": "The visible unauthorized access meets the incident definition.",
            },
        ],
        "evidence_for": ["evt_001"],
        "evidence_against": [],
        "missing_evidence": [],
        "alternative_hypotheses": [],
        "overall_confidence": 0.90,
        "abstain": False,
        "abstention_reason": None,
    }


def _review(recommended_verdict: str = "YES") -> dict:
    return {
        "claims": [
            {
                "claim_id": claim_id,
                "overall_label": "SUPPORTED",
                "axis_labels": {"citation": "SUPPORTED"},
                "rationale": "The cited event supports the exact wording.",
                "missing_evidence": [],
            }
            for claim_id in ("c1", "decision_1")
        ],
        "recommended_verdict": recommended_verdict,
        "decisive_claim_ids_requiring_review": [],
        "omitted_counterevidence_event_ids": [],
        "verifier_confidence": 0.90,
    }


class _FakeClient:
    model = "generator-model"
    provider = "test"
    model_revision = "test-revision"
    endpoint = "https://private.invalid"

    def __init__(self, *, review_verdict: str = "YES") -> None:
        self.review_verdict = review_verdict
        self.calls: list[dict] = []

    async def call(self, **kwargs) -> ChatCompletionResult:
        self.calls.append(kwargs)
        is_review = kwargs.get("seed", 0) >= 100_000
        content = json.dumps(_review(self.review_verdict) if is_review else _investigation())
        return ChatCompletionResult(
            content=content,
            response_json={"provider_private": "not persisted"},
            requested_model=kwargs.get("model") or self.model,
            returned_model=kwargs.get("model") or self.model,
            system_fingerprint="fp_test",
            input_tokens=100,
            output_tokens=50,
            total_tokens=150,
            latency_ms=12.5,
            http_status=200,
            endpoint_sha256="endpoint_hash",
            provider=self.provider,
            model_revision=self.model_revision,
        )


def test_json_parser_accepts_object_and_full_fence_only():
    assert parse_json_object('{"verdict":"YES"}') == {"verdict": "YES"}
    assert parse_json_object('```json\n{"verdict":"NO"}\n```') == {"verdict": "NO"}

    with pytest.raises(json.JSONDecodeError):
        parse_json_object('Here is the answer: {"verdict":"YES"}')
    with pytest.raises(TypeError):
        parse_json_object('[{"verdict":"YES"}]')


def test_client_records_model_and_usage_without_exposing_token():
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["model"] == "verifier-model"
        assert "response_format" not in payload
        assert request.headers["authorization"] == "Bearer secret-token"
        return httpx.Response(
            200,
            json={
                "model": "verifier-model@sha256:abc",
                "system_fingerprint": "server-fingerprint",
                "choices": [{"message": {"content": '{"ok":true}'}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
            },
        )

    async def exercise() -> ChatCompletionResult:
        transport = httpx.MockTransport(handler)
        http_client = httpx.AsyncClient(transport=transport)
        client = WarrantLLMClient(
            endpoint="https://private.invalid",
            token="secret-token",
            model="generator-model",
            provider="test-provider",
            model_revision="sha256:def",
            client=http_client,
        )
        async with client:
            result = await client.call(
                system_prompt="system",
                user_prompt="user",
                model="verifier-model",
            )
        await http_client.aclose()
        return result

    result = asyncio.run(exercise())
    assert result.requested_model == "verifier-model"
    assert result.returned_model == "verifier-model@sha256:abc"
    assert result.total_tokens == 12
    assert result.provider == "test-provider"
    assert "secret-token" not in repr(result)


def test_client_json_mode_requests_one_json_object():
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert payload["response_format"] == {"type": "json_object"}
        assert payload["think"] is False
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": '{"ok":true}'}}]},
        )

    async def exercise() -> None:
        http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = WarrantLLMClient(
            endpoint="https://private.invalid",
            client=http_client,
        )
        async with client:
            await client.call(
                system_prompt="system",
                user_prompt="user",
                json_mode=True,
                thinking=False,
            )
        await http_client.aclose()

    asyncio.run(exercise())


def test_client_supports_native_ollama_json_without_thinking():
    def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert request.url.path == "/api/chat"
        assert payload["format"] == "json"
        assert payload["think"] is False
        assert payload["stream"] is False
        assert payload["options"]["seed"] == 42
        return httpx.Response(
            200,
            json={
                "model": "local-model",
                "message": {"role": "assistant", "content": '{"ok":true}'},
                "prompt_eval_count": 10,
                "eval_count": 2,
            },
        )

    async def exercise() -> ChatCompletionResult:
        http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        client = WarrantLLMClient(
            endpoint="http://127.0.0.1:11434",
            model="local-model",
            provider="ollama-local",
            api_style="ollama",
            client=http_client,
        )
        async with client:
            result = await client.call(
                system_prompt="system",
                user_prompt="user",
                json_mode=True,
                thinking=False,
                seed=42,
            )
        await http_client.aclose()
        return result

    result = asyncio.run(exercise())
    assert result.content == '{"ok":true}'
    assert result.total_tokens == 12


def test_safe_error_redacts_endpoint_and_bearer_token():
    error = RuntimeError(
        "POST https://private.invalid/v1/chat/completions with Bearer super.secret-token failed"
    )
    serialized = json.dumps(_safe_error(error))
    assert "private.invalid" not in serialized
    assert "super.secret-token" not in serialized


def test_generator_verifier_run_preserves_raw_provenance(tmp_path: Path):
    client = _FakeClient()
    record = asyncio.run(run_case_condition(
        client,
        _case(),
        run_id="pytest-run",
        condition="generator_verifier",
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path,
        verifier_model="verifier-model",
    ))

    assert record["operational_status"] == "valid"
    assert record["exact_correct"] is True
    assert record["generator"]["parser_status"] == "valid"
    assert record["verifier"]["parser_status"] == "valid"
    assert client.calls[1]["model"] == "verifier-model"
    generator_call = record["generator"]["call"]
    assert "content" not in generator_call
    assert "response_json" not in generator_call
    assert len(generator_call["raw_response_sha256"]) == 64
    assert Path(generator_call["raw_response_path"]).read_text() == json.dumps(_investigation())


def test_reviewer_can_abstain_but_cannot_reverse_verdict(tmp_path: Path):
    abstaining = asyncio.run(run_case_condition(
        _FakeClient(review_verdict="INSUFFICIENT"),
        _case(),
        run_id="pytest-abstain",
        condition="generator_verifier",
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path / "abstain",
    ))
    reversed_review = asyncio.run(run_case_condition(
        _FakeClient(review_verdict="NO"),
        _case(),
        run_id="pytest-reverse",
        condition="generator_verifier",
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path / "reverse",
    ))

    assert abstaining["operational_status"] == "valid_abstained"
    assert abstaining["predicted_verdict"] == "INSUFFICIENT"
    assert reversed_review["operational_status"] == "review_failure"
    assert reversed_review["exact_correct"] is False


def test_review_conditions_share_generator_and_verifier_responses(tmp_path: Path):
    client = _FakeClient()
    conditions = [
        "llm_events_plus_alerts",
        "llm_self_review",
        "generator_verifier",
        "generator_verifier_abstention",
    ]
    records = asyncio.run(run_case_group(
        client,
        _case(),
        run_id="pytest-paired",
        conditions=conditions,
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path,
        verifier_model="verifier-model",
    ))

    assert len(client.calls) == 3  # one generator, one self-review, one verifier
    assert {record["condition"] for record in records} == set(conditions)
    assert {record["generation_group"] for record in records} == {"alerts_visible_shared"}
    assert len({record["generator_response_sha256"] for record in records}) == 1
    verifier_records = [
        record
        for record in records
        if record["condition"] in {"generator_verifier", "generator_verifier_abstention"}
    ]
    assert len({record["verifier"]["call"]["raw_response_sha256"] for record in verifier_records}) == 1

    summary = summarize_run(records)
    assert summary["artifact_integrity"]["ok"] is True
    assert summary["artifact_integrity"]["unique_raw_responses_checked"] == 3
    assert summary["conditions"]["llm_events_plus_alerts"]["attack_recall"] == 1.0
    assert (
        summary["paired_effects"]["shared_generation_reviews"]
        ["generator_verifier"]["generator_hash_match_rate"]
        == 1.0
    )
    assert summary["operations"]["overall"]["unique_calls"] == 3
    assert "canonical" in summary["by_variant"]
    assert "credential_compromise" in summary["by_family"]
    assert (
        summary["mechanical_axis_profiles"]["llm_events_plus_alerts"]
        ["decisive_claims"]["citation"]["unwarranted_rate"]
        == 0.0
    )


def test_artifact_integrity_detects_raw_response_tampering(tmp_path: Path):
    client = _FakeClient()
    record = asyncio.run(run_case_condition(
        client,
        _case(),
        run_id="pytest-integrity",
        condition="llm_events_only",
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path,
    ))
    path = Path(record["generator"]["call"]["raw_response_path"])
    path.write_text("tampered")

    integrity = verify_artifacts([record])
    assert integrity["ok"] is False
    assert "hash mismatch" in integrity["errors"][0]


def test_release_integrity_permits_only_complete_raw_omission(tmp_path: Path):
    client = _FakeClient()
    first = asyncio.run(run_case_condition(
        client,
        _case(),
        run_id="pytest-omitted-raw",
        condition="llm_events_only",
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path,
    ))
    second = asyncio.run(run_case_condition(
        client,
        _case(),
        run_id="pytest-omitted-raw",
        condition="llm_events_only",
        repetition=1,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path,
    ))
    first_path = Path(first["generator"]["call"]["raw_response_path"])
    second_path = Path(second["generator"]["call"]["raw_response_path"])

    first_path.unlink()
    strict = verify_artifacts([first])
    omitted = verify_artifacts([first], allow_omitted_raw=True)
    assert strict["ok"] is False
    assert omitted["ok"] is True
    assert omitted["raw_response_status"] == "omitted_by_release_policy"
    assert omitted["unique_raw_responses_missing"] == 1

    partial = verify_artifacts([first, second], allow_omitted_raw=True)
    assert partial["ok"] is False
    assert partial["raw_response_status"] == "incomplete"
    assert "partial raw-response set" in partial["errors"][0]
    assert second_path.exists()


def test_variant_contrast_is_paired_to_canonical_base_case(tmp_path: Path):
    canonical = asyncio.run(run_case_condition(
        _FakeClient(),
        _case(),
        run_id="pytest-variant-contrast",
        condition="llm_events_plus_alerts",
        repetition=0,
        temperature=0.1,
        max_tokens=4096,
        run_dir=tmp_path,
    ))
    mutated = copy.deepcopy(canonical)
    mutated.update({
        "case_id": "case_runner_001__misleading_alert_actor",
        "variant": "misleading_alert_actor",
        "predicted_verdict": "NO",
        "predicted_suspect": "user_99",
        "verdict_correct": False,
        "suspect_correct": False,
        "exact_correct": False,
    })
    summary = summarize_run([canonical, mutated])
    contrast = summary["variant_contrasts"]["misleading_alert_actor"][
        "llm_events_plus_alerts"
    ]
    assert contrast["paired_record_n"] == 1
    assert contrast["base_case_n"] == 1
    assert contrast["expected_verdict_change_rate"] == 0.0
    assert contrast["verdict_flip_rate"] == 1.0
    assert contrast["suspect_flip_rate"] == 1.0
    assert contrast["exact_accuracy_change_mutated_minus_canonical"] == -1.0


def test_resume_keys_include_case_condition_and_repetition(tmp_path: Path):
    records = tmp_path / "records.jsonl"
    records.write_text(
        json.dumps({"case_id": "c1", "condition": "llm_events_only", "repetition": 0})
        + "\n"
        + json.dumps({"case_id": "c1", "condition": "llm_events_only", "repetition": 1})
        + "\n"
    )

    assert _load_completed(records) == {
        "c1|llm_events_only|0",
        "c1|llm_events_only|1",
    }
