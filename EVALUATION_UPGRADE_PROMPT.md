# Claude Code Prompt — Evaluation Upgrade for the Forensic-LLM Paper

Copy everything below the line into Claude Code, run from the repository root
(`~/projects/cybersecurity`).

---

You are working in an existing research repository. The Python analysis engine
lives in `forensic-framework/`. Do NOT restructure it; extend it. The paper
(`conference_paper/paper.tex`) was reviewed with three evaluation criticisms
that you must solve **in this order of priority**:

1. Only 15 scenarios (no statistical power: McNemar p = 0.219).
2. All scenarios synthetic AND author-designed (designer bias).
3. Single model (Qwen-class 27B only).

Work autonomously. Verify every number you produce against persisted
artifacts. Never edit result JSONs by hand.

## Repository facts (do not rediscover; verify once)

- Scenario format: `forensic-framework/data/scenarios/scenario_N.json` with
  keys `scenario_id`, `name`, `label` (BENIGN|ATTACK), `description`,
  `events` (list of raw event dicts spanning 7 source types: auth,
  file_access, admin, network, database, web_server, email).
- Ground truth: `forensic-framework/data/ground_truth/ground_truth.json`,
  `{"scenarios": [...]}` with per-scenario `id`, `name`, `label`, `attacker`,
  `attack_steps`, `expected_detection`.
- Personas: `forensic-framework/data/user_baselines.json` (user_01..user_04:
  normal IPs, hours, directories).
- Rules: `forensic-framework/config/rules.yaml` (R001–R012). Do not tune them;
  the paper's claim depends on a frozen transparent baseline.
- Drivers: `run_pipeline.py` (generate→parse→normalize→timeline→rules→LLM),
  `run_evaluation.py`, `run_stress_tests.py`, `run_s15_ablation.py`.
- LLM client: `app/llm/client.py`, OpenAI-compatible chat-completions via
  `MODAL_ENDPOINT`/`MODAL_MODEL` env vars; temperature 0.1; mock mode when
  unset. Validator: `app/llm/hallucination_checker.py` (7 checks).
- Results land in `data/evaluation_results.json`,
  `data/llm_responses/`, `data/stress_tests/`, `data/ablation/`.
- 47 pytest tests must keep passing: `cd forensic-framework && pytest`.

## Task 1 — Programmatic scenario generator: 15 → 115 scenarios

Create `forensic-framework/app/ingestion/scenario_factory.py` plus driver
`generate_corpus.py`. Requirements:

- **Template families, not hand-written cases.** Implement parameterized
  generators for at least 10 families, each producing BENIGN and/or ATTACK
  variants: (a) normal baseline; (b) travel/conference noise; (c) credential
  compromise + exfiltration; (d) multi-day insider scope creep (2–10 days);
  (e) session hijack (mid-session IP change); (f) maintenance windows;
  (g) failed credential stuffing; (h) multi-stage infrastructure attack
  (SQLi → db_export → DNS tunnel); (i) decoy/misdirection (loud decoy user +
  quiet attacker); (j) legitimate bulk peaks (quarter close, audit season,
  migration). Randomize: actors, day counts, event counts, volumes,
  timestamps, IPs, resource paths, ticket metadata, decoy loudness, and
  attacker quietness — all from a seeded RNG (`--seed`, default 42) so the
  corpus is exactly reproducible.
- **Anti-designer-bias controls (the paper must be able to cite these):**
  1. Generation is parameter-driven from declared distributions, committed in
     `config/corpus_spec.yaml` — reviewers can audit the space, and the
     authors never see/edit individual generated scenarios before scoring.
  2. Hold out the calibration set: the LLM prompt was tuned on S1–S15 only;
     mark all new scenarios `holdout: true` in ground truth and report
     holdout-only metrics separately. Do not touch `app/llm/prompts.py`.
  3. Target a 40/60 benign/attack mix and include ≥15 "hard benign"
     scenarios (high alert volume, BENIGN label) so FP behavior is powered.
- Emit 100 new scenarios as `scenario_16.json` … `scenario_115.json`, append
  matching ground-truth entries, extend `user_baselines.json` to ≥10 personas
  (generator-created, seeded), and write `data/corpus_manifest.json`
  (family, seed, parameters, holdout flag per scenario).
- Add pytest coverage: schema validity of every generated scenario; label
  balance; determinism under fixed seed; no underscore-prefixed
  ground-truth leakage into events.

## Task 2 — Run the full pipeline + multi-model comparison

- Generalize `app/llm/client.py` minimally: read `LLM_ENDPOINTS` as a JSON
  list of `{name, url, model, token_env}`; add `--model NAME` to
  `run_pipeline.py` and result-path namespacing
  (`data/llm_responses/<model>/…`, `data/evaluation_results_<model>.json`).
- Models to run (all open-weight, all OpenAI-compatible via vLLM or Ollama;
  ask the user for endpoints if none are configured — do NOT silently mock):
  1. the existing Qwen-class 27B (primary),
  2. Llama-3.1-8B-Instruct (or largest Llama available to the user),
  3. Mistral-Small / Mistral-7B-Instruct.
- Execution budget: full 115-scenario corpus on the primary model;
  the 100-scenario holdout on all three models; N=5 repeated runs on a
  stratified 20-scenario subset (for variance); rule engine on everything
  (it is free and deterministic).
- Extend the S15-style ablation: run rule-context vs no-rule-context on
  every *hard benign* scenario and on every decoy-family scenario, 5 runs
  per condition. This tests whether rule-context amplification and decoy
  misattribution generalize — currently shown for single scenarios only.

## Task 3 — Statistics that survive review

Create `run_statistics.py` producing `data/statistics_report.json` + a
LaTeX-ready table file:

- Verdict accuracy per system per corpus slice (all / holdout-only /
  benign-only / attack-only) with exact Clopper–Pearson 95% CIs.
- McNemar exact test (rules vs primary LLM; LLM vs LLM pairwise) on the
  holdout corpus. With ~100 paired scenarios this is adequately powered.
- Bootstrap (10k resamples) CIs for accuracy deltas and for citation
  validity; per-family accuracy breakdown table.
- Run-to-run variance from the N=5 subset: per-scenario verdict flip rate,
  Fleiss' kappa across runs.
- Grounding metrics: invalid-citation rate with CI, chronology violations,
  per hallucination-type counts — across all models.

## Task 4 — (Stretch, only after 1–3 are green) Real-data adapter

- Implement `app/ingestion/adapters/lanl_auth.py`: map the LANL
  "Comprehensive, Multi-Source Cyber-Security Events" auth records onto the
  unified schema (auth source type only; document the field mapping in the
  module docstring). Build investigation windows around the published
  red-team events as ATTACK slices and matched windows without red-team
  activity as BENIGN slices. The dataset is a manual download — generate
  the adapter + a `--lanl-dir` flag and a clear README section; do not
  fabricate data if the files are absent.
- Same skeleton (stub + mapping doc, no fake data) for DARPA OpTC.

## Task 5 — Update the paper

In `conference_paper/` (LaTeX, IEEEtran, compiles with
`latexmk -pdf paper.tex`):

- Replace the 15-scenario headline with holdout-corpus results; keep S1–S15
  reported separately as the calibration set. Update abstract, Table I,
  Fig. 8 (regenerate from new data — figure scripts live in the session
  notes; rebuild equivalent matplotlib scripts under `conference_paper/`),
  statistics paragraph (drop p = 0.219, insert the new McNemar/bootstrap
  results whatever they show — including if the LLM advantage shrinks),
  limitations (synthetic→generator-based; single→multi-model), and
  revision_history.md (v7 entry).
- Honesty constraints, non-negotiable: report holdout results even if worse;
  keep S14/S15-style failures and any new failure families discovered; never
  average away verdict flips — report them.

## Acceptance criteria

- `pytest` green, including new tests.
- `data/corpus_manifest.json` lists 115 scenarios, seeded, ≥40 benign.
- `data/statistics_report.json` exists with CIs + McNemar on ≥100 holdout
  scenarios for ≥1 model (≥3 models if endpoints were provided).
- Paper recompiles at ≤10 pages with regenerated numbers traceable to
  artifacts (no hand-typed results).
- A final summary stating: old vs new accuracy, new p-values, any new
  failure modes found, and what was NOT achieved and why.

---

### Notes for the user (not part of the prompt)

- Tasks 1 and 3 run with zero infrastructure. Task 2 needs LLM endpoints —
  budget roughly 115 + 300 + 100×2-ish ≈ 600–800 LLM calls for the full
  matrix; at ~30s/call that's a few hours wall-clock, parallelizable.
- LANL data: https://csr.lanl.gov/data/cyber1/ (free, registration).
  OpTC: https://github.com/FiveDirections/OpTC-data.
- If the holdout results weaken the headline (plausible — calibration-set
  results usually flatter), that is the honest paper. The reviewer scoring
  you at 8.3 will score a flattering-but-unpowered paper lower than an
  honest powered one.
