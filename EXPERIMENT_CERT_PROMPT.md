# Claude Code Prompt — Autonomous CERT Replay (zero user interaction)

Copy everything below the line into Claude Code, run from
`~/projects/cybersecurity`. It is designed to run end-to-end without asking
you anything.

---

You are running the final experimental cycle for an existing research paper,
fully autonomously. Do not ask the user questions. When you hit a problem:
diagnose, fix, retry (up to 3 attempts per step), or take the documented
fallback. There are exactly TWO conditions under which you may stop and
report instead of continuing: (1) the CERT dataset cannot be downloaded by
any means, (2) no live LLM endpoint responds. Everything else you solve
yourself.

## Context (verified facts — do not rediscover)

- Engine: `forensic-framework/` (Python 3.11). Unified event schema:
  `event_id, timestamp (tz-aware), source_type, user, action, resource,
  source_ip, status, session_id, severity, metadata`.
- Existing adapter pattern to copy: `app/ingestion/adapters/lanl_auth.py`
  (379 lines: streaming reader, field-mapping docstring, window builder,
  `load_scenarios(dir) -> scenario dicts`, raises FileNotFoundError when
  data absent).
- Scenario dict shape consumed by the pipeline:
  `{scenario_id, name, label (BENIGN|ATTACK), description, events:[...]}`
  with ground truth appended to `data/ground_truth/ground_truth.json`
  (`{"scenarios":[...]}`, fields `id, name, label, attacker, attack_steps,
  expected_detection`).
- LLM: OpenAI-compatible endpoint from `.env`
  (`MODAL_ENDPOINT`, `MODAL_MODEL=fusion-gemma`), temperature 0.1,
  max_tokens 2048, 32K context. Client: `app/llm/client.py`. The client
  falls back to a deterministic mock when the endpoint is missing —
  **mock results must never reach the paper**: every persisted response
  must have `is_mock: false`; assert this programmatically before any
  statistics run.
- Validator: `app/llm/hallucination_checker.py` (do not modify checks).
- Prompt: `app/llm/prompts.py` is FROZEN. Do not edit it.
- Stats: `run_statistics.py` → `data/statistics_report.json` (Clopper–
  Pearson CIs, exact McNemar, bootstrap). Tests: `pytest` (59 green now;
  keep them green).
- Paper: `conference_paper/paper.tex`, IEEEtran, compiles with
  `latexmk -pdf paper.tex` to exactly 10 pages currently. Hard cap 11.

## Step 1 — Obtain CERT r4.2

The CERT Insider Threat Test Dataset is published by CMU on KiltHub
(doi:10.1184/R1/12841247). Find the current download URL by web search if
the canonical one fails. You need release **r4.2** (`r4.2.tar.bz2`,
~1.7 GB) and the **answers** archive (insider ground truth). Download to
`~/data/cert/`, verify archive integrity (re-download once on failure),
extract `logon.csv, device.csv, file.csv, email.csv, http.csv, LDAP/`.
If r4.2 is unreachable after retries, fall back to r6.2 or r5.2 and adapt
(answers format differs slightly — handle it). Only if NO release is
obtainable: stop, report, done.

## Step 2 — Adapter: `app/ingestion/adapters/cert_insider.py`

Map five CERT streams onto the unified schema (document the full field
mapping in the module docstring):

| CERT file | source_type | action examples |
|---|---|---|
| logon.csv | auth | login / logout (Logon/Logoff) |
| device.csv | admin | usb_connect / usb_disconnect |
| file.csv | file_access | file_copy (to removable media) |
| email.csv | email | mail_sent (size, attachments, to/from) |
| http.csv | web_server | http_request (url) |

- `user` = CERT user id; `resource` = filename/url/pc; `source_ip` absent →
  use `"pc:<pc_id>"`; `session_id` = `"<user>_<pc>_<date>"`; severity via
  the existing severity map; timestamps tz-aware (assume UTC).
- Ground truth from the answers archive: each insider has user id +
  active period + scenario type. Window unit = **per-user-month**:
  for each labeled insider, one ATTACK window covering their active month(s)
  (split months >1); sample BENIGN windows as user-months from users NOT in
  the answers file, matched by event volume so class isn't separable by
  count alone — compute and record the event-count distributions of both
  classes in the manifest; if their medians differ by >25%, resample.
- Target: 20 ATTACK + 20 BENIGN windows, seeded RNG (42), manifest at
  `data/cert_manifest.json` (window, user, month, family, event counts).
- **Context budget**: cap each window at 220 events to fit 32K context. If
  a user-month exceeds the cap, keep all admin/device/file events, then
  downsample logon/http/email uniformly per day, and record
  `downsampled: true` + original count in the manifest. State this in the
  paper.
- Tests: add `tests/test_cert_adapter.py` (schema validity, label balance,
  volume matching, determinism, no-answers-leakage into events). Keep all
  existing tests green.

## Step 3 — Run

- `run_real_data.py --source cert ...` (extend it) → scenarios written,
  rules + LLM + validator executed, results in
  `data/evaluation_results_cert.json`, responses in
  `data/llm_responses/cert/`. Reuse the resumable pattern from
  `run_llm_corpus.py` (save each response immediately).
- Endpoint failures: retry with exponential backoff (3×); on repeated HTTP
  4xx/5xx halve max_tokens once; on context overflow re-downsample that
  window (cap 160) and mark it. If the endpoint is dead entirely: stop,
  report (condition 2). After the run, assert `is_mock == false` for all
  40 responses; abort statistics if any mock slipped through.

## Step 4 — Statistics

Extend `run_statistics.py` with a `cert` slice: accuracy per system with
exact 95% CIs, McNemar, grounding metrics (citation validity, fabricated
IDs, chronology), and a per-insider-scenario-type breakdown. The two
pre-registered questions (answer both, whichever way the data falls):
1. Does the perfect-attack-recall / high-benign-FP asymmetry from the
   synthetic holdout replicate on third-party data?
2. Does multi-day insider recall (the S4/S13 result) hold on CERT's real
   insider cases?

## Step 5 — Paper integration

- New Evaluation subsection "Third-Party Benchmark Replay (CERT r4.2)":
  setup (5 of 7 source types, per-user-month windows, volume matching,
  downsampling caveat), results table, and one paragraph per
  pre-registered question. Update the limitations paragraph (synthetic →
  synthetic + third-party benchmark; author-designed critique now answered
  twice). Touch the abstract ONLY if a headline finding changes.
- Regenerate any affected figure from artifacts (a CERT confusion matrix
  if it adds information). All numbers traceable to
  `data/statistics_report.json` — no hand-typed results.
- `revision_history.md`: v10 entry. Recompile: `latexmk -pdf paper.tex`,
  ≤11 pages, 0 undefined references. If page count exceeds 11, tighten
  float spacing or drop the least informative existing table — do not cut
  results or limitations.

## Step 6 — Final report (write to CERT_RUN_SUMMARY.md)

State: windows built (with volume-match evidence), accuracy both systems
with CIs, McNemar p, grounding numbers, answers to both pre-registered
questions, any new failure modes, every fallback you took and why, and
anything NOT achieved with the reason. Honesty over flattery: if the
methodology breaks on CERT, that result goes in the paper as a finding,
prominently, not in a footnote.

## Non-negotiables

- Never fabricate events, results, or citations. Never hand-edit result
  JSONs. Never let `is_mock: true` data into statistics or the paper.
- Frozen: `app/llm/prompts.py`, validator checks, `config/rules.yaml`.
- Keep 59+ tests green; add new ones for the adapter.
- Report weakening results with the same prominence as strengthening ones.
