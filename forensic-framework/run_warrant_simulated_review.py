#!/usr/bin/env python3
"""Run blinded language-model simulations of warrant reviewers.

The output is sensitivity evidence only. It is intentionally separate from the
human-annotation CSVs and cannot satisfy the expert-validation gate.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from app.evaluation.warrant_simulated import (
    SIMULATED_REVIEW_SCHEMA_VERSION,
    deterministic_batches,
    read_jsonl,
    sha256_bytes,
    simulated_system_prompt,
    simulated_user_prompt,
    validate_simulated_response,
    reviewer_batch_config,
)
from app.llm.warrant_client import (
    WarrantLLMClient,
    endpoint_fingerprint,
    parse_json_object,
    prompt_fingerprint,
)


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_CONFIG = PROJECT_ROOT / "config" / "warrant_simulated_review.yaml"


def _git_commit() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def _safe_error(exc: Exception, spec: dict[str, Any]) -> str:
    message = str(exc)
    for secret in (spec.get("endpoint"), spec.get("token"), str(PROJECT_ROOT)):
        if secret:
            message = message.replace(str(secret), "[REDACTED]")
    return message[:1000]


def _resolved_reviewers(config: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for source in config["reviewers"]:
        endpoint = source.get("endpoint") or os.getenv(source.get("endpoint_env", ""), "")
        model = source.get("model") or os.getenv(source.get("model_env", ""), "")
        token = os.getenv(source.get("token_env", ""), "") if source.get("token_env") else ""
        if not endpoint or not model:
            raise ValueError(f"reviewer {source['reviewer_id']} lacks endpoint or model")
        output.append({
            **source,
            "endpoint": endpoint.rstrip("/"),
            "model": model,
            "token": token,
        })
    return output


def _public_reviewer(spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "reviewer_id": spec["reviewer_id"],
        "panel_role": spec["panel_role"],
        "provider": spec["provider"],
        "api_style": spec["api_style"],
        "model": spec["model"],
        "profile": spec["profile"],
        "temperature": spec["temperature"],
        "thinking": spec.get("thinking"),
        "seed": spec["seed"],
        "role_note": spec["role_note"],
        "batch": spec.get("batch"),
        "endpoint_sha256": endpoint_fingerprint(spec["endpoint"]),
        "system_prompt_sha256": hashlib.sha256(
            simulated_system_prompt(spec["profile"]).encode()
        ).hexdigest(),
    }


def _load_or_create_manifest(
    *,
    run_dir: Path,
    run_id: str,
    package_dir: Path,
    config_path: Path,
    items_path: Path,
    config: dict[str, Any],
    reviewers: list[dict[str, Any]],
) -> dict[str, Any]:
    path = run_dir / "manifest.json"
    manifest = {
        "simulated_review_schema_version": SIMULATED_REVIEW_SCHEMA_VERSION,
        "run_id": run_id,
        "validity_boundary": (
            "language-model sensitivity panel; not human or expert validation"
        ),
        "annotation_package": package_dir.relative_to(PROJECT_ROOT).as_posix(),
        "annotation_manifest_sha256": sha256_bytes(
            (package_dir / "manifest.json").read_bytes()
        ),
        "annotation_items_sha256": sha256_bytes(items_path.read_bytes()),
        "item_count": len(read_jsonl(items_path)),
        "config_path": config_path.relative_to(PROJECT_ROOT).as_posix(),
        "config_sha256": sha256_bytes(config_path.read_bytes()),
        "batch": config["batch"],
        "reviewers": [_public_reviewer(spec) for spec in reviewers],
        "source_git_commit": _git_commit(),
    }
    if path.exists():
        existing = json.loads(path.read_text())
        for key in (
            "simulated_review_schema_version",
            "run_id",
            "annotation_manifest_sha256",
            "annotation_items_sha256",
            "config_sha256",
            "reviewers",
        ):
            if existing.get(key) != manifest.get(key):
                raise ValueError(f"existing simulated-run manifest differs at {key}")
        return existing
    run_dir.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


async def _run_reviewer(
    *,
    spec: dict[str, Any],
    items: list[dict[str, Any]],
    run_dir: Path,
    batch_config: dict[str, Any],
) -> dict[str, Any]:
    reviewer_id = spec["reviewer_id"]
    reviewer_dir = run_dir / "reviewers" / reviewer_id
    judgments_path = reviewer_dir / "judgments.jsonl"
    failures_path = reviewer_dir / "failures.jsonl"
    existing = read_jsonl(judgments_path) if judgments_path.exists() else []
    completed = {row["annotation_id"] for row in existing}
    if len(completed) != len(existing):
        raise ValueError(f"duplicate existing judgments for {reviewer_id}")
    remaining = [item for item in items if item["annotation_id"] not in completed]
    effective_batch = reviewer_batch_config(batch_config, spec)
    batches = deterministic_batches(
        remaining,
        reviewer_id=reviewer_id,
        max_items=int(effective_batch["max_items"]),
        max_chars=int(effective_batch["max_chars"]),
    )
    raw_dir = reviewer_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    call_index = len(list(raw_dir.glob("*.json")))
    new_successes = 0
    final_failures = 0
    system_prompt = simulated_system_prompt(spec["profile"])

    async with WarrantLLMClient(
        endpoint=spec["endpoint"],
        token=spec["token"],
        model=spec["model"],
        provider=spec["provider"],
        api_style=spec["api_style"],
        timeout_seconds=600,
    ) as client:
        async def process(batch: list[dict[str, Any]], depth: int = 0) -> None:
            nonlocal call_index, new_successes, final_failures
            expected_ids = [item["annotation_id"] for item in batch]
            user_prompt = simulated_user_prompt(batch)
            digest = hashlib.sha256("|".join(expected_ids).encode()).hexdigest()[:16]
            last_error: Exception | None = None
            for attempt in range(int(effective_batch["retry_attempts"])):
                call_index += 1
                call_seed = int(spec["seed"]) + int(digest[:8], 16) + attempt
                try:
                    result = await client.call(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        temperature=float(spec["temperature"]),
                        max_tokens=int(effective_batch["max_tokens"]),
                        seed=call_seed,
                        json_mode=True,
                        thinking=spec.get("thinking"),
                    )
                    raw_payload = {
                        "simulated_review_schema_version": SIMULATED_REVIEW_SCHEMA_VERSION,
                        "reviewer_id": reviewer_id,
                        "annotation_ids": expected_ids,
                        "attempt": attempt + 1,
                        "response": result.response_json,
                    }
                    raw_path = raw_dir / f"call-{call_index:04d}-{digest}-a{attempt + 1}.json"
                    raw_bytes = (
                        json.dumps(raw_payload, indent=2, sort_keys=True) + "\n"
                    ).encode()
                    raw_path.write_bytes(raw_bytes)
                    parsed = parse_json_object(result.content)
                    reviews = validate_simulated_response(parsed, expected_ids)
                    call_metadata = {
                        "reviewer_id": reviewer_id,
                        "profile": spec["profile"],
                        "requested_model": result.requested_model,
                        "returned_model": result.returned_model,
                        "provider": result.provider,
                        "endpoint_sha256": result.endpoint_sha256,
                        "model_revision": result.model_revision,
                        "system_fingerprint": result.system_fingerprint,
                        "prompt_sha256": prompt_fingerprint(system_prompt, user_prompt),
                        "raw_response_path": raw_path.relative_to(PROJECT_ROOT).as_posix(),
                        "raw_response_sha256": sha256_bytes(raw_bytes),
                        "input_tokens": result.input_tokens,
                        "output_tokens": result.output_tokens,
                        "total_tokens": result.total_tokens,
                        "latency_ms": result.latency_ms,
                        "seed": call_seed,
                        "temperature": spec["temperature"],
                        "thinking": spec.get("thinking"),
                    }
                    for review in reviews:
                        _append_jsonl(judgments_path, {
                            "simulated_review_schema_version": SIMULATED_REVIEW_SCHEMA_VERSION,
                            "annotation_id": review["annotation_id"],
                            "reviewer_id": reviewer_id,
                            "review": review,
                            "call": call_metadata,
                        })
                        completed.add(review["annotation_id"])
                        new_successes += 1
                    return
                except Exception as exc:  # failures are retained and retried/split
                    last_error = exc
                    _append_jsonl(failures_path, {
                        "simulated_review_schema_version": SIMULATED_REVIEW_SCHEMA_VERSION,
                        "reviewer_id": reviewer_id,
                        "annotation_ids": expected_ids,
                        "attempt": attempt + 1,
                        "depth": depth,
                        "error_type": type(exc).__name__,
                        "error": _safe_error(exc, spec),
                    })
            if len(batch) > 1:
                midpoint = len(batch) // 2
                await process(batch[:midpoint], depth + 1)
                await process(batch[midpoint:], depth + 1)
                return
            final_failures += 1
            print(
                f"{reviewer_id}: failed {expected_ids[0]} after retries: "
                f"{type(last_error).__name__ if last_error else 'unknown'}",
                flush=True,
            )

        for index, batch in enumerate(batches, 1):
            await process(batch)
            print(
                f"{reviewer_id}: batch {index}/{len(batches)}; "
                f"complete={len(completed)}/{len(items)}",
                flush=True,
            )
    return {
        "reviewer_id": reviewer_id,
        "complete": len(completed),
        "expected": len(items),
        "new_successes": new_successes,
        "final_failures": final_failures,
        "calls": call_index,
    }


async def async_main(args: argparse.Namespace) -> int:
    load_dotenv(PROJECT_ROOT / ".env")
    config_path = args.config.resolve()
    config = yaml.safe_load(config_path.read_text())
    reviewers = _resolved_reviewers(config)
    selected_reviewers = [
        reviewer for reviewer in reviewers if reviewer["panel_role"] == "consensus"
    ]
    if args.reviewer:
        requested = set(args.reviewer)
        selected_reviewers = [
            reviewer for reviewer in reviewers
            if reviewer["reviewer_id"] in requested
        ]
        missing = requested.difference(
            reviewer["reviewer_id"] for reviewer in selected_reviewers
        )
        if missing:
            raise ValueError(f"unknown reviewer IDs: {sorted(missing)}")

    package_dir = args.package_dir.resolve()
    items_path = package_dir / "blind" / "items.jsonl"
    items = read_jsonl(items_path)
    if args.limit:
        items = items[: args.limit]
    run_dir = args.output_dir.resolve()
    _load_or_create_manifest(
        run_dir=run_dir,
        run_id=args.run_id,
        package_dir=package_dir,
        config_path=config_path,
        items_path=items_path,
        config=config,
        reviewers=reviewers,
    )
    summaries = []
    for reviewer in selected_reviewers:
        summaries.append(await _run_reviewer(
            spec=reviewer,
            items=items,
            run_dir=run_dir,
            batch_config=config["batch"],
        ))
    print(json.dumps(summaries, indent=2, sort_keys=True))
    return 0 if all(row["complete"] == row["expected"] for row in summaries) else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package_dir", type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--reviewer", action="append")
    parser.add_argument("--limit", type=int, help="pilot only; do not analyze as complete")
    return asyncio.run(async_main(parser.parse_args()))


if __name__ == "__main__":
    raise SystemExit(main())
