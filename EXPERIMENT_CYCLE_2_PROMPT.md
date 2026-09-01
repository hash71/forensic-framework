# Claude Code Prompt — Final Experimental Cycle (Real Data + Multi-Model)

Prerequisites YOU must arrange before running this (the only blockers):

1. **LANL data**: register at https://csr.lanl.gov/data/cyber1/ and download
   `auth.txt.gz` and `redteam.txt` into a local directory, e.g.
   `~/data/lanl/`.
2. **Model endpoints**: at least one additional open-weight model behind an
   OpenAI-compatible endpoint (vLLM or Ollama), e.g.
   Llama-3.1-8B-Instruct and/or Mistral-7B-Instruct. Note each endpoint
   URL + model name.

Copy everything below the line into Claude Code, run from
`~/projects/cybersecurity`.

---

You are finishing the experimental program for an existing paper. The
analysis engine is `forensic-framework/` (115-scenario corpus already
evaluated on Gemma; statistics in `data/statistics_report.json`); the paper
is `conference_paper/paper.tex` (10 pages, compiles with latexmk). Reviewer
verdict: writing is done; the only remaining upgrades are (A) real-data
replay and (B) multi-model replication. Do not refactor working code, do
not touch prompts (`app/llm/prompts.py` is frozen), and never hand-edit
result JSONs.

## Task A — LANL replay

1. The adapter `app/ingestion/adapters/lanl_auth.py` is already built and
   tested (raises FileNotFoundError without data). Ask me for the
   `--lanl-dir` path, then run:
   `python run_real_data.py --source lanl --lanl-dir <path> --n-attack 20 --n-benign 20 --window-minutes 10`
2. Run the rule engine and the primary LLM over the resulting 40 windows
   (reuse `run_llm_corpus.py` patterns; results namespaced under
   `data/evaluation_results_lanl.json`, responses under
   `data/llm_responses/lanl/`).
3. Add a `lanl` slice to `run_statistics.py`: accuracy + CIs per system,
   McNemar, grounding metrics. LANL windows are auth-only, single source
   type — state this clearly; do not present it as a full seven-source
   replay.
4. Sanity constraints: ground truth comes only from `redteam.txt` windows;
   if class balance or window construction looks degenerate (e.g., all
   windows trivially separable by event count), report that honestly
   instead of celebrating the number.

## Task B — Multi-model replication

1. Ask me for endpoint URL(s) + model name(s). Configure via the existing
   env-var mechanism; add per-model namespacing if `run_llm_corpus.py`
   lacks it.
2. Run each additional model over the **100-scenario holdout** (skip
   calibration; it only matters for the Gemma-tuned prompt).
3. Extend `run_statistics.py`: per-model accuracy by slice (holdout,
   attack-only, benign-only, hard-benign), pairwise McNemar, grounding
   metrics per model. The key question to answer: **is the perfect-recall /
   high-benign-FP asymmetry Gemma-specific or model-general?** Report
   whichever answer the data gives.
4. If budget is tight, the minimum publishable version is one extra model
   on two slices: all 56 holdout attacks + all 34 hard-benign (90 calls).

## Task C — Paper integration (only after A/B data exists)

- Add a "Real-Data Replay (LANL)" subsection to Evaluation: setup,
  auth-only caveat, results table row(s), what transfers and what doesn't.
- Add a multi-model column/row block to the headline and hard-benign
  tables; update the single-model limitation paragraph to reflect what was
  actually run; update abstract numbers only if the headline findings
  change.
- Regenerate affected figures from the new statistics report (confusion
  matrices per model if informative).
- Update `revision_history.md` (v10) and recompile
  (`latexmk -pdf paper.tex`); keep ≤10 pages if possible, ≤11 hard cap.
- Honesty constraints unchanged: report results that weaken the story,
  keep all failure cases, no hand-typed numbers — everything traceable to
  `data/*.json`.

## Acceptance

- `data/evaluation_results_lanl.json` + `data/statistics_report.json` with
  lanl and per-model slices; all numbers in the paper traceable to them.
- 59+ tests still green.
- Final summary: LANL accuracy both systems, whether the recall/FP
  asymmetry replicated on other models, any new failure modes, and what
  was not achieved and why.
