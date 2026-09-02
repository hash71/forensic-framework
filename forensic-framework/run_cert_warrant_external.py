#!/usr/bin/env python3
"""Run the atomic-warrant pipeline on the external CERT r4.2 windows."""

from __future__ import annotations

import argparse
import asyncio
import json
from datetime import datetime, timezone

from app.ingestion.warrant_benchmark import PROJECT_ROOT
from app.ingestion.warrant_external import (
    CERT_CASES_PATH,
    load_cert_warrant_cases,
)
from app.llm.warrant_runner import run_experiment


VALID_CONDITIONS = {
    "llm_events_only",
    "llm_events_plus_alerts",
    "llm_self_review",
    "generator_verifier",
    "generator_verifier_abstention",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--conditions",
        default=(
            "llm_events_plus_alerts,generator_verifier,"
            "generator_verifier_abstention"
        ),
    )
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--max-tokens", type=int, default=4096)
    parser.add_argument("--model")
    parser.add_argument("--verifier-model")
    parser.add_argument("--provider")
    parser.add_argument("--model-revision")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--run-id")
    parser.add_argument("--no-resume", action="store_true")
    args = parser.parse_args()

    conditions = [item.strip() for item in args.conditions.split(",") if item.strip()]
    unknown = set(conditions).difference(VALID_CONDITIONS)
    if unknown:
        parser.error(f"unknown conditions: {', '.join(sorted(unknown))}")
    cases = sorted(load_cert_warrant_cases(), key=lambda case: case["case_id"])
    if args.limit is not None:
        cases = cases[: args.limit]
    if not cases:
        parser.error("case selection is empty")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = args.run_id or f"external-cert-r4_2-{timestamp}"
    run_dir = PROJECT_ROOT / "data" / "warrant_runs" / run_id
    manifest = asyncio.run(
        run_experiment(
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
            benchmark_path=CERT_CASES_PATH,
            benchmark_label_semantics=(
                "latent_incident_label_not_visible_evidence_warrant"
            ),
        )
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
