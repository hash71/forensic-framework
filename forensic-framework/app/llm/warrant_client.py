"""Provenance-preserving OpenAI-compatible client for warrant experiments."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Self

import httpx
from dotenv import load_dotenv

from app.ingestion.warrant_benchmark import PROJECT_ROOT

load_dotenv(PROJECT_ROOT / ".env")


@dataclass(frozen=True)
class ChatCompletionResult:
    content: str
    response_json: dict[str, Any]
    requested_model: str
    returned_model: str | None
    system_fingerprint: str | None
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None
    latency_ms: float
    http_status: int
    endpoint_sha256: str
    provider: str
    model_revision: str | None


def endpoint_fingerprint(endpoint: str) -> str:
    """Record endpoint identity without writing a private URL to artifacts."""

    return hashlib.sha256(endpoint.rstrip("/").encode()).hexdigest()


def prompt_fingerprint(system_prompt: str, user_prompt: str) -> str:
    payload = json.dumps(
        {"system": system_prompt, "user": user_prompt},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def parse_json_object(content: str) -> dict[str, Any]:
    """Parse one JSON object without repairing or coercing model prose."""

    text = content.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    value = json.loads(text)
    if not isinstance(value, dict):
        raise TypeError("Model response must be one JSON object.")
    return value


class WarrantLLMClient:
    """Minimal asynchronous client with reproducibility metadata."""

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        token: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        model_revision: str | None = None,
        timeout_seconds: float = 300.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.endpoint = (endpoint or os.getenv("MODAL_ENDPOINT", "")).rstrip("/")
        self.token = token if token is not None else os.getenv("MODAL_TOKEN", "")
        self.model = model or os.getenv("MODAL_MODEL", "fusion-gemma")
        self.provider = provider or os.getenv("LLM_PROVIDER", "openai-compatible")
        self.model_revision = model_revision or os.getenv("MODAL_MODEL_REVISION")
        self.timeout_seconds = timeout_seconds
        self._external_client = client is not None
        self._client = client
        if not self.endpoint:
            raise ValueError("No OpenAI-compatible endpoint is configured.")

    async def __aenter__(self) -> Self:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout_seconds,
                follow_redirects=True,
            )
        return self

    async def __aexit__(self, *_args: object) -> None:
        if self._client is not None and not self._external_client:
            await self._client.aclose()
            self._client = None

    async def call(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        seed: int | None = None,
        model: str | None = None,
    ) -> ChatCompletionResult:
        if self._client is None:
            raise RuntimeError("Use WarrantLLMClient as an async context manager.")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        requested_model = model or self.model
        payload: dict[str, Any] = {
            "model": requested_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "max_tokens": max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        if seed is not None:
            payload["seed"] = seed

        started = time.perf_counter()
        response = await self._client.post(
            f"{self.endpoint}/v1/chat/completions",
            headers=headers,
            json=payload,
        )
        latency_ms = (time.perf_counter() - started) * 1000
        response.raise_for_status()
        data = response.json()
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise ValueError("Endpoint returned no chat-completion message content.") from exc
        usage = data.get("usage") or {}
        return ChatCompletionResult(
            content=str(content),
            response_json=data,
            requested_model=requested_model,
            returned_model=data.get("model"),
            system_fingerprint=data.get("system_fingerprint"),
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            total_tokens=usage.get("total_tokens"),
            latency_ms=latency_ms,
            http_status=response.status_code,
            endpoint_sha256=endpoint_fingerprint(self.endpoint),
            provider=self.provider,
            model_revision=self.model_revision,
        )
