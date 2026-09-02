# Forensic Framework

A forensic log analysis framework comparing **rule-based detection** vs **LLM analysis** (Qwen 3.5-27B) across 15 investigation scenarios. Built as a thesis research project.

## Key Finding

> **LLM verdict accuracy 14/15 (93.3%) vs rule engine 10/15 (66.7%). Validator records no invalid event-ID citations in 13 of 15 scenarios.**

On benign-but-noisy scenarios, the rule engine fires 76 alerts in aggregate (33 on the after-hours-maintenance scenario alone) while the LLM produces a single verdict-level false positive (S15, end-of-quarter activity). A five-run no-rule-context ablation on S15 reverses the verdict to `NO` on all five runs (`data/ablation/S15_*.json`), supporting the rule-context-amplification hypothesis: the false positive comes from how the LLM interprets the rule-alert artefact, not from the underlying timeline.

Two limits bound the contribution: (S14) the LLM's binary verdict is correct but it picks the decoy actor as the suspect — citation grounding does not catch wrong-suspect-with-real-evidence; (S15) rule-alert context amplifies a benign scenario into a false attack verdict, reversed by the ablation.

## What It Does

1. **Ingests logs** from 7 server types (authentication, file access, admin, network, database, web, email) — 297 events across 15 scenarios
2. **Normalises** raw logs into a common schema (with OCSF v1.1 / ECS 8.x mappings)
3. **Analyses** the same correlated timeline with two methods in parallel:
   - **Rule engine**: 12 threshold-style correlation rules (R001–R012)
   - **LLM analyst**: Qwen 3.5-27B with structured forensic prompting; every claim must cite an event identifier from the input
4. **Validates** the LLM output through a seven-check evidence-grounding validator (event-ID existence, chronology, actor/entity consistency, selected volume claims)
5. **Evaluates** both methods against ground truth — verdict accuracy, F1 against attack steps, false-positive rate, citation-grounding violations
6. **Stress tests** the LLM against evidence removal, noise injection, temporal jitter, format variations

## Dashboard

A 4-page Streamlit dashboard presents the framework and results:

| Page | Purpose |
|------|---------|
| **Operations Center** | Monitoring overview — 7 servers, key metrics, clickable incident table |
| **Investigation Console** | Per-incident deep dive — timeline, event log, detection comparison, LLM narrative |
| **Research Findings** | The thesis story — where rules fail, where LLM fails, stress test results |
| **Infrastructure** | Pipeline architecture, detection methods side-by-side, rule inventory |

## The 15 Scenarios

| # | Scenario | Truth | Rules | LLM |
|---|----------|-------|-------|-----|
| S01 | Normal Baseline | Benign | ✅ | ✅ |
| S02 | Noisy Benign | Benign | ✅ | ✅ |
| S03 | Obvious Attack | Attack | ✅ | ✅ |
| S04 | Subtle Insider Threat | Attack | ✅ | ✅ |
| S05 | Session Hijack | Attack | ❌ | ✅ |
| S06 | After-Hours Maintenance | Benign | ❌ | ✅ |
| S07 | Failed Credential Stuffing | Benign | ✅ | ✅ |
| S08 | Full Infrastructure Attack | Attack | ✅ | ✅ |
| S09 | Incomplete Logs | Attack | ✅ | ✅ |
| S10 | Delayed Events | Attack | ❌ | ✅ |
| S11 | Benign Then Compromised | Attack | ✅ | ✅ |
| S12 | Conflicting Signals | Attack | ❌ | ✅ |
| S13 | Ultra-Slow Exfiltration | Attack | ❌ | ✅ |
| S14 | False Flag / Misdirection | Attack | ✅ | ✅\* |
| S15 | End-of-Quarter Bulk | Benign | ✅ | ❌† |

\* S14: LLM's binary verdict is correct (`YES` against `ATTACK`) but it picks the decoy as the suspect; ground-truth attacker is `user_02`, LLM names `user_04`. Suspect-attribution failure, not a verdict failure.

† S15: Rule-context amplification. A five-run no-rule-context ablation reverses the verdict to `NO` on all five runs (see `data/ablation/`).

Rules fail on 5 scenarios that require contextual reasoning (S5 session IP change, S6 legitimate after-hours maintenance, S10 out-of-order timestamps, S12 conflicting signals, S13 multi-day exfiltration). The LLM fails on 1 scenario at the verdict level (S15, end-of-quarter legitimate bulk activity); a no-rule-context ablation reverses this to the correct verdict.

## Architecture

```
┌─────────────┐    ┌───────────┐    ┌─────────────┐    ┌──────────────┐    ┌────────────┐
│  7 Servers  │ →  │ Collection│ →  │Normalization│ →  │ Rules + LLM  │ →  │ Evaluation │
│             │    │  297 evts │    │ Standardized│    │   Analysis   │    │ 15 scenarios│
└─────────────┘    └───────────┘    └─────────────┘    └──────────────┘    └────────────┘
```

### Detection Rules (12)

| ID | Name | Checks |
|----|------|--------|
| R001 | unusual_login_ip | Logins from IPs not in user's `normal_ips` |
| R002 | off_hours_access | Activity outside the user's `normal_hours` |
| R003 | privilege_escalation | Any `privilege_change` action |
| R004 | bulk_download | More than 5 `file_download` events within 30 min |
| R005 | cross_department_access | Resource directory not in user's `normal_directories` |
| R006 | log_deletion | Any `log_delete` action (anti-forensics indicator) |
| R007 | failed_login_spike | ≥ 2 login failures within a 5-minute window |
| R008 | privilege_then_download | `privilege_change` followed by `file_download` within 30 min |
| R009 | dns_tunnel_detection | More than 20 DNS queries to the same domain within 5 min |
| R010 | sql_injection_attempt | Web event with status 500 and SQL keywords in URL |
| R011 | data_exfiltration_volume | Total outbound bytes > 100 MB within 30 min |
| R012 | lateral_movement | Same user authenticated against ≥ 3 server types within 30 min |

### LLM Output Schema

For each scenario, the LLM produces:
- **Verdict** (attack / clear)
- **Confidence** (high / medium / low)
- **Narrative** (plain-English explanation)
- **Suspect** (primary user)
- **Attack chain** (step-by-step reconstruction with event IDs)
- **Evidence for** / **Evidence against** (cited event IDs)
- **Gaps** (missing information)

## Running Locally

### Prerequisites

- Python 3.11+
- `pip install -r requirements.txt`

### Start the Dashboard

```bash
streamlit run dashboard.py
```

Opens at http://localhost:8501.

### Re-run the Pipeline

```bash
python run_pipeline.py       # Ingest, normalize, run rules, call LLM
python run_evaluation.py     # Score verdicts against ground truth
python run_stress_tests.py   # Run degradation / noise / jitter tests
```

### Run Tests

```bash
pytest tests/
```

## Evaluation Metrics

Each scenario is scored on:

- **Verdict accuracy** — Does rule/LLM verdict match ground truth?
- **Precision** — Of alerts raised, how many are true positives?
- **F1 score** — Harmonic mean of precision and recall
- **False positive rate** — Benign events incorrectly flagged
- **Hallucination count** (LLM only) — Fabricated event references, unsupported claims, timeline errors
- **Evidence grounding %** (LLM only) — Claims backed by actual log evidence

## Stress Tests

The LLM is tested under 4 adversarial conditions:

| Test | What it checks |
|------|----------------|
| **Format Resilience** | Raw logs vs full pipeline — can LLM handle unprocessed input? |
| **Evidence Removal** | Accuracy as 0%, 20%, 40%, 60%, 80% of events are deleted |
| **Noise Injection** | Accuracy as ratio of noise events to real events grows |
| **Temporal Jitter** | Accuracy when timestamps are shifted by 5min / 30min / 2hr |

## Project Structure

```
forensic-framework/
├── app/                    # Core pipeline (FastAPI-based)
│   ├── ingestion/          # Log collection and generation
│   ├── normalizer/         # Raw log → standardized schema
│   ├── rules/              # Rule engine (9 rules)
│   ├── llm/                # LLM client, prompts, hallucination checker
│   ├── correlation/        # Cross-event pattern detection
│   ├── timeline/           # Event timeline construction
│   ├── evaluation/         # Verdict scoring against ground truth
│   └── reporting/          # Analysis output
├── config/
│   └── rules.yaml          # Rule definitions and thresholds
├── data/
│   ├── scenarios/          # 15 scenario definitions
│   ├── raw_logs/           # Per-scenario raw log files
│   ├── normalized/         # Normalized events, timelines, rule results
│   ├── llm_responses/      # LLM output per scenario
│   ├── ground_truth/       # Expected verdicts
│   ├── stress_tests/       # Stress test results
│   └── evaluation_results.json
├── pages/                  # Dashboard pages (Streamlit)
│   ├── 1_Investigation.py
│   ├── 2_Research.py
│   └── 3_Infrastructure.py
├── tests/                  # Pytest test suite
├── dashboard.py            # Dashboard entry point (Operations Center)
├── dashboard_utils.py      # Shared utilities, CSS, data loading
├── run_pipeline.py         # End-to-end pipeline runner
├── run_evaluation.py       # Evaluation runner
├── run_stress_tests.py     # Stress test runner
└── requirements.txt
```

## Tech Stack

- **Python 3.11** — pipeline and analysis
- **Streamlit 1.56** — dashboard UI
- **Plotly** — timeline visualizations and charts
- **FastAPI** — backend services
- **Qwen 3.5-27B** — LLM analyst (via API)
- **Pydantic** — data validation
- **pytest** — test suite

## License

No repository-wide public license has been selected. Default copyright rules
apply except where a component states its own license. See
`docs/release_license_audit.md` for the author decision record and the
monorepo-root `THIRD_PARTY_NOTICES.md` for third-party terms. Do not describe
this repository as open source until the copyright holders approve and add the
corresponding license files.
