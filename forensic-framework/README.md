# Forensic Framework

A forensic log analysis framework comparing **rule-based detection** vs **LLM analysis** (Qwen 3.5-27B) across 15 investigation scenarios. Built as a thesis research project.

## Key Finding

> **LLM analysis achieves 93% accuracy (14/15 scenarios) vs 67% (10/15) for the rule engine — with 1 false positive vs 76.**

The LLM's advantage comes from contextual reasoning: understanding user intent, correlating events across time and sources, and recognizing attack patterns that static threshold rules miss.

## What It Does

1. **Ingests logs** from 7 server types (authentication, file access, admin, network, database, web, email) — 297 events across 15 scenarios
2. **Normalizes** raw logs into a common schema
3. **Analyzes** the same normalized data with two methods in parallel:
   - **Rule engine**: 9 threshold-based detection rules
   - **LLM analyst**: Qwen 3.5-27B with structured forensic prompting
4. **Evaluates** both methods against ground truth — precision, recall, F1, false positive rate, hallucination count
5. **Stress tests** the LLM against evidence removal, noise injection, temporal jitter, format variations

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
| S14 | False Flag / Misdirection | Attack | ✅ | ✅ |
| S15 | End-of-Quarter Bulk | Benign | ✅ | ❌ |

Rules fail on 5 scenarios that require contextual reasoning (session IP change detection, legitimate-vs-malicious after-hours activity, out-of-order timestamps, fabricated VPN logs, multi-day exfiltration patterns). The LLM fails on 1 scenario where legitimate end-of-quarter bulk activity resembles exfiltration patterns.

## Architecture

```
┌─────────────┐    ┌───────────┐    ┌─────────────┐    ┌──────────────┐    ┌────────────┐
│  7 Servers  │ →  │ Collection│ →  │Normalization│ →  │ Rules + LLM  │ →  │ Evaluation │
│             │    │  297 evts │    │ Standardized│    │   Analysis   │    │ 15 scenarios│
└─────────────┘    └───────────┘    └─────────────┘    └──────────────┘    └────────────┘
```

### Detection Rules (9)

| ID | Name | Checks |
|----|------|--------|
| R001 | unusual_login_ip | Logins from IPs not in user's baseline |
| R002 | off_hours_access | Activity outside business hours (09:00–17:00) |
| R003 | privilege_escalation | User elevating own access privileges |
| R004 | bulk_download | Downloads exceeding N files in a short window |
| R005 | cross_department_access | Directory access outside user's department |
| R006 | log_deletion | Log file deletion (anti-forensics indicator) |
| R007 | failed_login_spike | Multiple failed logins in a short window |
| R008 | privilege_then_download | Escalation followed by bulk download |
| R012 | lateral_movement | Session activity spanning multiple hosts |

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

Research project. Not licensed for commercial use.
