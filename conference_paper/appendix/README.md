# Appendix — Supporting Artifacts

All files are derived directly from the persisted evaluation artifacts in
`forensic-framework/data/` (commit-state of the evaluated revision). Nothing
here is hand-edited.

| File | Contents | Source artifact |
|---|---|---|
| `per_scenario_results.csv` | Full 15-scenario results: ground truth, rule and LLM verdicts, correctness flags, step F1, alert-level FP counts and load, citation counts and invalid references, chronology flag, identified suspect, grounding % | `data/evaluation_results.json` |
| `stress_test_results.json` | Raw stress-test records: (A) raw-log vs full-pipeline (S3–S5), (B) evidence removal 0–80% × 3 trials (S3–S4), (C) noise injection up to 1:5 (S3–S4), (D) timestamp jitter (S3) | `data/stress_tests/stress_test_results.json` |
| `S15_ablation_summary.json` | Five-run rule-context vs no-rule-context ablation verdicts for S15 (5/5 YES vs 5/5 NO) | `data/ablation/S15_ablation_summary.json` |

Reproduction: `run_pipeline.py` → `run_evaluation.py` → `run_stress_tests.py`
→ `run_s15_ablation.py` in `forensic-framework/` (Docker stack:
`docker compose up -d`; LLM endpoint configured via `MODAL_ENDPOINT`/`MODAL_MODEL`
or any OpenAI-compatible local server).
