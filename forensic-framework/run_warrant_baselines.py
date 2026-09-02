#!/usr/bin/env python3
"""Run transparent and classical baselines on the warrant benchmark."""

from __future__ import annotations

import json

from app.evaluation.warrant_baselines import run_baselines, write_baseline_results


def main() -> int:
    summary = write_baseline_results(run_baselines())
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

