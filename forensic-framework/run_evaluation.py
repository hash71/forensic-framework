#!/usr/bin/env python3
"""Run evaluation and print the comparison table."""

import argparse
import sys
from pathlib import Path

# Ensure project root is on sys.path for imports
sys.path.insert(0, str(Path(__file__).parent))

PROJECT_ROOT = Path(__file__).parent


def _pipeline_data_exists() -> bool:
    """Check if the pipeline output files exist for evaluation."""
    normalized_dir = PROJECT_ROOT / "data" / "normalized"
    llm_dir = PROJECT_ROOT / "data" / "llm_responses"

    if not normalized_dir.exists():
        return False

    # Check for at least one set of required files
    events = list(normalized_dir.glob("scenario_*_events.json"))
    rules = list(normalized_dir.glob("scenario_*_rule_results.json"))
    responses = list(llm_dir.glob("scenario_*_response.json")) if llm_dir.exists() else []

    return len(events) > 0 and len(rules) > 0 and len(responses) > 0


def _run_pipeline_first():
    """Run the full pipeline to generate required data files."""
    print("=" * 60)
    print("Pipeline data not found. Running pipeline first...")
    print("=" * 60)
    from run_pipeline import run_pipeline

    run_pipeline(use_mock=True)
    print()


def run_evaluation():
    """Run Phase 4 evaluation and display results."""
    from app.evaluation.evaluator import evaluate_all, print_comparison_table

    print("=" * 60)
    print("=== Phase 4: Evaluation ===")
    print("=" * 60)

    results = evaluate_all()

    print()
    print_comparison_table(results)

    # Check if results are based on mock data
    llm_dir = PROJECT_ROOT / "data" / "llm_responses"
    if llm_dir.exists():
        import json

        for resp_file in sorted(llm_dir.glob("scenario_*_response.json")):
            try:
                with open(resp_file, "r") as f:
                    resp = json.load(f)
                if resp.get("source") == "mock":
                    print()
                    print(
                        "WARNING: Results based on MOCK LLM responses. "
                        "Set MODAL_ENDPOINT and run with --no-mock for real analysis."
                    )
                    break
            except (json.JSONDecodeError, OSError):
                continue

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run Phase 4 evaluation and print the comparison table."
    )
    parser.add_argument(
        "--run-pipeline",
        action="store_true",
        default=False,
        help="Run the full pipeline first if data files are missing.",
    )
    args = parser.parse_args()

    if args.run_pipeline and not _pipeline_data_exists():
        _run_pipeline_first()
    elif not _pipeline_data_exists() and not args.run_pipeline:
        print(
            "ERROR: Pipeline data files not found. Run 'python3 run_pipeline.py' first, "
            "or use '--run-pipeline' to auto-run."
        )
        sys.exit(1)

    run_evaluation()
