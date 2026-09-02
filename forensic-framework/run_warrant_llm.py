#!/usr/bin/env python3
"""Run resumable LLM conditions on selected warrant-benchmark cases."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone

from app.ingestion.warrant_benchmark import PROJECT_ROOT, load_cases
from app.llm.warrant_runner import run_experiment

VALID_CONDITIONS = {
    "llm_events_only",
    "llm_events_plus_alerts",
    "llm_self_review",
    "generator_verifier",
    "generator_verifier_abstention",
}


def _select_cases(
    *,
    split: str,
    variants: set[str] | None,
    families: set[str] | None,
    limit: int | None,
) -> list[dict]:
    selected = [case for case in load_cases() if case["split"] == split]
    if variants:
        selected = [case for case in selected if case["variant"] in variants]
    if families:
        selected = [case for case in selected if case["family"] in families]
    selected.sort(key=lambda case: case["case_id"])
    return selected[:limit] if limit is not None else selected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=["development", "test"], default="development")
    parser.add_argument("--variants", default="canonical")
    parser.add_argument("--families", default="")
    parser.add_argument("--conditions", default="llm_events_only,llm_events_plus_alerts")
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--model", help="Generator model identifier; defaults to MODAL_MODEL.")
    parser.add_argument("--verifier-model", help="Independent verifier model identifier.")
    parser.add_argument("--provider", help="Provider label recorded in provenance metadata.")
    parser.add_argument("--model-revision", help="Immutable generator model revision or digest.")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--run-id")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    conditions = [item.strip() for item in args.conditions.split(",") if item.strip()]
    unknown = set(conditions).difference(VALID_CONDITIONS)
    if unknown:
        parser.error(f"unknown conditions: {', '.join(sorted(unknown))}")
    variants = {item.strip() for item in args.variants.split(",") if item.strip()} or None
    families = {item.strip() for item in args.families.split(",") if item.strip()} or None
    cases = _select_cases(
        split=args.split,
        variants=variants,
        families=families,
        limit=args.limit,
    )
    if not cases:
        parser.error("case selection is empty")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = args.run_id or f"{args.split}-{timestamp}"
    run_dir = PROJECT_ROOT / "data" / "warrant_runs" / run_id
    manifest = asyncio.run(run_experiment(
        cases,
        run_id=run_id,
        conditions=conditions,
        repetitions=args.repetitions,
        concurrency=args.concurrency,
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        run_dir=run_dir,
        resume=not args.no_resume,
        generator_model=args.model,
        verifier_model=args.verifier_model,
        provider=args.provider,
        model_revision=args.model_revision,
    ))
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
