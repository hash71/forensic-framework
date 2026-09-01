#!/usr/bin/env python3
"""Run the LLM (Gemma) over the entire 115-scenario corpus.

Resumable: skips scenarios whose response JSON already exists unless
--force is passed. Saves responses incrementally so an interruption mid-run
loses at most the in-flight scenario.

Output:
    data/llm_responses/scenario_{N}_response.json   -- one per scenario

Usage:
    python run_llm_corpus.py            # all 115, skip already-done
    python run_llm_corpus.py --force    # re-run everything
    python run_llm_corpus.py --only 1-15    # subset
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.llm.client import call_modal_llm
from app.llm.prompts import LLM_SYSTEM_PROMPT, build_scenario_prompt


PROJECT_ROOT = Path(__file__).resolve().parent
SCENARIOS_DIR = PROJECT_ROOT / "data" / "scenarios"
RESPONSES_DIR = PROJECT_ROOT / "data" / "llm_responses"


def _scenario_ids() -> list[int]:
    nums = []
    for p in SCENARIOS_DIR.glob("scenario_*.json"):
        try:
            nums.append(int(p.stem.split("_")[1]))
        except ValueError:
            continue
    return sorted(nums)


def _parse_range(spec: str) -> set[int]:
    out: set[int] = set()
    for piece in spec.split(","):
        piece = piece.strip()
        if "-" in piece:
            lo, hi = piece.split("-")
            out.update(range(int(lo), int(hi) + 1))
        elif piece:
            out.add(int(piece))
    return out


async def _run_one(num: int, max_retries: int) -> tuple[int, str, float, str | None]:
    """Run one scenario. Returns (num, verdict, seconds, error_msg)."""
    start = time.monotonic()
    prompt = build_scenario_prompt(num)
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            result = await call_modal_llm(
                prompt=prompt, system_prompt=LLM_SYSTEM_PROMPT,
            )
            elapsed = time.monotonic() - start
            out_path = RESPONSES_DIR / f"scenario_{num}_response.json"
            with open(out_path, "w") as f:
                json.dump(result, f, indent=2)
            return num, result.get("verdict", "?"), elapsed, None
        except Exception as exc:
            last_err = f"{type(exc).__name__}: {str(exc)[:200]}"
            if attempt < max_retries:
                await asyncio.sleep(2 ** attempt)
    elapsed = time.monotonic() - start
    return num, "ERR", elapsed, last_err


async def _main_async(args) -> int:
    RESPONSES_DIR.mkdir(parents=True, exist_ok=True)

    ids = _scenario_ids()
    if args.only:
        wanted = _parse_range(args.only)
        ids = [n for n in ids if n in wanted]
    todo = []
    skipped = 0
    for n in ids:
        out_path = RESPONSES_DIR / f"scenario_{n}_response.json"
        if out_path.exists() and not args.force:
            skipped += 1
            continue
        todo.append(n)
    print(f"corpus run: {len(todo)} scenarios to process, {skipped} skipped, "
          f"{len(ids)} in total", flush=True)
    if not todo:
        return 0

    summary = []
    grand_start = time.monotonic()
    for i, n in enumerate(todo, 1):
        s_num, verdict, elapsed, err = await _run_one(n, args.retries)
        msg = (f"[{i:3d}/{len(todo)}] scenario_{n}: verdict={verdict} "
               f"({elapsed:.1f}s)")
        if err:
            msg += f"  ERROR: {err}"
        print(msg, flush=True)
        summary.append({"scenario": s_num, "verdict": verdict,
                         "seconds": elapsed, "error": err})

    total = time.monotonic() - grand_start
    ok = sum(1 for s in summary if s["error"] is None)
    fail = len(summary) - ok
    print(f"\ndone: {ok} ok, {fail} failed, {total:.0f}s wall, "
          f"{total / max(1, len(summary)):.1f}s avg/scenario", flush=True)

    # Save run summary
    summary_path = RESPONSES_DIR / "corpus_run_summary.json"
    with open(summary_path, "w") as f:
        json.dump({"total": len(summary), "ok": ok, "failed": fail,
                   "wall_seconds": total, "items": summary}, f, indent=2)
    return 0 if fail == 0 else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the LLM over the 115-scenario corpus.",
    )
    parser.add_argument("--force", action="store_true",
                        help="Re-run scenarios whose response already exists.")
    parser.add_argument("--only", type=str, default=None,
                        help='Comma-separated scenario ids or ranges, e.g. "1-15,50,80".')
    parser.add_argument("--retries", type=int, default=2,
                        help="Per-scenario retry budget on transient errors.")
    args = parser.parse_args()
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    sys.exit(main())
