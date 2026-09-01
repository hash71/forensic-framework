#!/usr/bin/env python3
"""Ingest a real-world cyber dataset and emit scenarios in the unified schema.

Supports:
    --source lanl   -- LANL "Comprehensive Multi-Source Cyber-Security Events"
    --source cert   -- CERT Insider Threat Test Dataset r4.2
    --source optc   -- DARPA OpTC (skeleton only)

The output is a set of scenario JSON files written to a target directory
(default: `data/real_scenarios/`). These can then be fed through the
existing pipeline (run_pipeline.py) — but note that the rule engine's
user_baselines won't cover real-world usernames, so most rule checks will
no-op on real-data scenarios. The LLM is unaffected.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.ingestion.adapters import lanl_auth, optc, cert_insider


PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUT = PROJECT_ROOT / "data" / "real_scenarios"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Ingest a real-world cyber dataset into the unified schema.",
    )
    parser.add_argument("--source",
                        choices=["lanl", "optc", "cert"], required=True)
    parser.add_argument("--lanl-dir", type=Path,
                        help="Directory with auth.txt(.gz) + redteam.txt(.gz)")
    parser.add_argument("--optc-dir", type=Path,
                        help="Directory containing OpTC ecar-twosix files")
    parser.add_argument("--cert-dir", type=Path,
                        default=Path("~/data/cert").expanduser(),
                        help="Directory with r4.2.tar.bz2 + answers.tar.bz2")
    parser.add_argument("--n-attack", type=int, default=20)
    parser.add_argument("--n-benign", type=int, default=20)
    parser.add_argument("--window-minutes", type=int, default=10,
                        help="(LANL) half-width of each investigation window")
    parser.add_argument("--max-events-per-window", type=int, default=220,
                        help="(CERT) per-window event cap for LLM context")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    extra_manifest: dict = {}

    if args.source == "lanl":
        if not args.lanl_dir:
            parser.error("--lanl-dir is required for --source lanl")
        scenarios = lanl_auth.load_scenarios(
            lanl_dir=args.lanl_dir,
            n_attack=args.n_attack, n_benign=args.n_benign,
            window_minutes=args.window_minutes,
            seed=args.seed,
        )
    elif args.source == "cert":
        scenarios, cert_manifest = cert_insider.load_scenarios(
            cert_dir=args.cert_dir,
            n_attack=args.n_attack, n_benign=args.n_benign,
            max_events_per_window=args.max_events_per_window,
            seed=args.seed,
            progress=print,
        )
        extra_manifest["cert"] = cert_manifest
    elif args.source == "optc":
        # NotImplementedError is intentional — see optc.py docstring.
        scenarios = optc.load_scenarios(args.optc_dir)
    else:
        parser.error(f"unknown source: {args.source}")

    for s in scenarios:
        out_path = args.out / f"{s['scenario_id']}.json"
        with open(out_path, "w") as f:
            json.dump(s, f, indent=2)

    manifest = {
        "source": args.source,
        "n_scenarios": len(scenarios),
        "n_attack": sum(1 for s in scenarios if s["label"] == "ATTACK"),
        "n_benign": sum(1 for s in scenarios if s["label"] == "BENIGN"),
        "out_dir": str(args.out),
        "seed": args.seed,
        **extra_manifest,
    }
    with open(args.out / "manifest.json", "w") as f:
        json.dump(manifest, f, indent=2)
    print(json.dumps({"source": args.source,
                       "n_scenarios": manifest["n_scenarios"],
                       "n_attack": manifest["n_attack"],
                       "n_benign": manifest["n_benign"],
                       "out_dir": str(args.out)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
