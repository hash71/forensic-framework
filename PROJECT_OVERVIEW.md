# Project Overview

**Working Title:** *Augmenting Rule-Based Private-Cloud Forensic Investigation with Evidence-Grounded LLM Reasoning*

(Old title was *A Privacy-Preserving LLM-Assisted Framework for Post-Incident Forensic Investigation in Private Cloud Environments* — reframed because privacy is a deployment constraint, not the headline contribution. The contribution is the controlled comparison between rules and LLM reasoning under strict evidence grounding.)

### Framing Note: Forensic Triage, Not Real-Time Detection

This system does **not** replace real-time intrusion detection. It supports **post-incident forensic triage** — reconstructing timelines, identifying suspicious evidence chains, and producing evidence-grounded investigative narratives over already-collected logs. The paper avoids the phrase "detects insider threats." It uses "improves forensic classification and explanation of incident scenarios."

---

## 1. What We Are Trying To Achieve

### The Problem

When a security incident hits a **private cloud** (an organization running its own infrastructure rather than AWS/Azure/GCP), forensic investigation is painful:

- Logs are scattered across auth servers, file servers, network devices, databases, web servers, mail servers, and admin layers.
- There is no equivalent of AWS CloudTrail or GuardDuty for private cloud.
- Investigators manually correlate evidence to reconstruct what happened — slow, expert-dependent, error-prone.
- Rule-based detection (the standard approach) has two well-known failure modes:
  - **Cries wolf** on legitimate-but-unusual behavior (travel, conferences, cross-team work, maintenance).
  - **Misses subtle attacks** where no single event crosses an alert threshold but the aggregate pattern across days is suspicious (slow insider exfiltration, scope creep).

### The Research Question

> **Does LLM-assisted reasoning, given structured private-cloud evidence, improve post-incident forensic understanding compared with rule-based analysis alone — without introducing unacceptable hallucinations?**

### The Proposal

A pipeline that does three things in order:

1. **Normalize** logs from heterogeneous private-cloud sources (auth, file_access, admin, network, database, web_server, email) into a unified event schema.
2. **Reconstruct a correlated forensic timeline** with chronological ordering and session grouping.
3. **Run both a rule engine and an LLM** over the same structured evidence, with the LLM constrained to only cite event IDs that actually exist in the input (anti-hallucination).

### What We Want To Show

- The LLM, given structured evidence (not raw logs), **correctly classifies** subtle multi-day insider scenarios that rule output mislabels — particularly scope-creep where reads gradually become downloads.
- The LLM correctly **dismisses benign-but-noisy** scenarios that rules over-flag (conference travel, maintenance windows).
- The LLM produces **no invalid event-ID citations under the implemented validator** — claims are bound to real evidence in the input.
- An **open-weight model** running on the organization's own compute is sufficient — forensic data does not leave the security boundary.

The LLM is **not used as an unconstrained investigator**. It is used as a **constrained reasoning layer over normalized forensic evidence**, whose claims must remain tied to verifiable event citations.

### Contribution, In One Sentence

A reproducible, controlled comparison showing that an open-weight LLM, when given structured forensic evidence and strict citation constraints, materially improves scenario-level forensic classification in private-cloud environments compared with rule-based analysis alone — with no measured invalid event-ID citations and with failure modes characterized rather than hidden.

---

## 2. Tech Stack

| Layer | Component | Notes |
|---|---|---|
| Language | Python 3.11 (Docker), 3.13 (local dev) | Both work |
| Database | PostgreSQL 15 via Docker | 4 tables, 177 events loaded |
| Python backend | FastAPI | 14 endpoints |
| PHP orchestration | Laravel | 18 API routes (audit + proxy layer) |
| Frontend | Streamlit | 5-tab dashboard, dark/light mode |
| LLM serving | Modal (Qwen 3.5-27B `fusion-brain`) | Endpoint-agnostic — swappable for vLLM/Ollama/TGI |
| Anti-hallucination | Custom validator (7 checks) | Event-id grounding, chronology, volume claims |
| Schema interop | OCSF v1.1 + ECS 8.x mapping | For real-world deployability |
| Containers | Dockerfile + docker-compose.yml | Postgres + FastAPI + Streamlit on one network |
| Tests | pytest (47 cases, all passing) | Unit + integration |
| Dependencies | 10 Python deps | Minimal — sqlalchemy, fastapi, streamlit, httpx, pyyaml, pytest, etc. |

---

## 3. What's Built — Layer By Layer

### 3.1 Backend (Python — `forensic-framework/`)

The core analysis engine. End-to-end pipeline implemented.

```
data/scenarios/*.json (7 source types per scenario)
    ↓
app/ingestion/log_generator.py    →  data/raw_logs/
    ↓
app/ingestion/parser.py            (parses 7 log formats with distinct raw fields)
    ↓
app/normalizer/normalizer.py       →  data/normalized/ + PostgreSQL
app/normalizer/ocsf_mapping.py     (OCSF v1.1 + ECS 8.x export)
    ↓
app/timeline/timeline.py           (chronological ordering + session grouping)
    ↓
app/correlation/correlator.py      (cross-source event linking)
    ↓
┌────────────────────────────┐     ┌─────────────────────────────┐
│ app/rules/rule_engine.py   │     │ app/llm/                     │
│   12 detection rules        │     │   prompts.py                 │
│   (R001–R012)               │     │   client.py (Modal/local)    │
│                             │     │   hallucination_checker.py   │
└────────────────────────────┘     └─────────────────────────────┘
    ↓                                    ↓
app/evaluation/evaluator.py        (10+ metrics)
    ↓
app/reporting/reporter.py          →  data/reports/
```

**FastAPI** (`app/main.py`): 14 endpoints exposing scenarios, raw logs, normalized events, timeline, rule alerts, LLM analysis, evaluation results, and reports.

**Status:** Implemented and executed. Real LLM runs completed across 15 scenarios.

### 3.2 Orchestration Layer (Laravel — `forensic-laravel/`)

A Laravel orchestration layer was implemented to demonstrate auditability and API integration — 6 controllers, 18 API routes, an `AuditService` writing to an `audit_logs` table, and a `ForensicEngineClient` that proxies to the Python FastAPI. **For the paper this gets one paragraph at most.** The core experimental pipeline lives in the Python forensic engine; Laravel is production framing, not a research contribution.

### 3.3 Frontend (Streamlit — `forensic-framework/dashboard.py`)

5-tab interactive dashboard:

1. **Scenarios** — pick scenario, view events, raw logs
2. **Timeline** — Gantt chart of events, session groupings
3. **Detection** — rule alerts and LLM verdict side-by-side, kill-chain visualization
4. **Evaluation** — comparison table, radar chart, heatmap
5. **Stress Tests** — event removal, noise injection, timestamp jitter results

Dark/light theme toggle. Multipage support via `pages/` directory.

**Status:** Implemented and running.

### 3.4 Docker

```yaml
docker compose up -d
```

Brings up:
- `db` — Postgres 15 on port `5434:5432` with healthcheck and persistent volume
- `app` — Python 3.11 container running both FastAPI (port 8000) and Streamlit (port 8501)

Modal endpoint and token injected via env vars; mocks gracefully if absent.

**Status:** Working. Three-service stack (db + fastapi + streamlit) starts cleanly.

### 3.5 Data

- **15 scenario JSON files** under `data/scenarios/` (originally 4 in the proposal — expanded for empirical strength)
- **Ground truth** for each scenario
- **User baselines** (4 personas: financial analyst, senior dev, HR specialist, junior accountant)
- **12 detection rules** in `config/rules.yaml`

### 3.6 Evaluation Harness

`run_pipeline.py` runs Phases 1–3 end-to-end. `run_evaluation.py` computes the comparison table. `run_stress_tests.py` runs the four stress dimensions (event removal, noise injection, timestamp jitter, raw-logs baseline).

---

## 4. Headline Results (Real LLM, Not Mock)

**Verdict accuracy across 15 scenarios:**

| System | Correct | Accuracy |
|---|---|---|
| Rule Engine | 9/15 | 60% |
| **LLM (Qwen 3.5)** | **14/15** | **93%** |
| Invalid event-ID citations under validator | 0 | — |

### Precise Hallucination Claim

We do **not** claim the LLM is hallucination-free in general. We claim, precisely, that under the implemented validator, the LLM produced zero invalid event-ID citations across the evaluated scenarios. The validator covers some hallucination types and not others:

| Hallucination type | Checked? | Example |
|---|---|---|
| Nonexistent event ID | Yes | cites `evt_999` when no such event exists |
| Chronology violation | Yes | claims event B preceded event A when timestamps disagree |
| Unsupported volume claim | Yes | says "large download" without matching event evidence |
| Actor / entity inconsistency | Yes | names a user/IP not present in the evidence |
| Causal overclaim | Partial | says "user *intended* exfiltration" — intent is not directly verifiable |
| Missing alternative explanation | Limited | does not always surface maintenance / travel as a counter-hypothesis |

This distinction must appear in the paper's Results and Discussion sections.

**Per-scenario evaluation (subset shown):**

| Scenario | Ground Truth | Rules | LLM | Rule F1 | LLM F1 | FP% | Hallucinations |
|---|---|---|---|---|---|---|---|
| S1: Normal | BENIGN | no_alert ✓ | NO ✓ | 0.00 | 0.00 | 0% | 0 |
| S2: Noisy (travel) | BENIGN | suspicious ✓ | NO ✓ | 0.00 | 0.00 | 76% | 0 |
| S3: Obvious attack | ATTACK | attack ✓ | YES ✓ | 0.33 | 0.91 | 0% | 0 |
| S4: 3-day insider | ATTACK | attack ✓ | YES ✓ | 0.10 | 0.91 | 0% | 0 |
| S5: Session hijack | ATTACK | suspicious ✗ | YES ✓ | 0.86 | 0.83 | 0% | 0 |
| S6: Maintenance | BENIGN | attack ✗ | NO ✓ | 0.00 | 0.00 | 132% | 0 |
| S14: Decoy misdirection | ATTACK | — | partial ✗ | — | — | — | 0 |
| S15: End-of-quarter bulk | BENIGN | suspicious | YES ✗ | — | — | — | 0 |

**Honest negative findings (these strengthen the paper, not weaken it):**

- **S14** — LLM identified the *decoy* (user_04) as the suspect; missed the real quiet attacker (user_02). Misdirection works.
- **S15** — LLM amplified rule false positives into an incorrect attack verdict; on raw logs *without* rule context it correctly said NO.
- These show **where LLM-assisted forensics breaks**, which is exactly what a discussion section needs.

---

## 5. Literature Review — Status

**What exists:**

- `Paper8_LitReview_Writeup.docx` — one paper's lit review already drafted
- `Paper8_LitReview_Presentation.pptx` — slide deck for it
- `research_plan.html` — original research plan with cited sources

**Important clarification:** The PDFs in `guidelines_and_samples/Papers/` (Cloud Forensics, Cloud Availability, Secure Computation, etc.) are **format/style exemplars only** — they show how to write a standard ACM/IEEE paper. They are *not* topically related to this research and should not be cited as related work.

**The actual related-work survey needs to cover:**

- LLM-assisted security analysis and SOC augmentation (recent 2023–2025 literature)
- Specifically the 2025 paper finding ChatGPT alone underperforms rule-based timeline analysis — directly motivates our hybrid approach
- Cloud forensics methodologies (private cloud focus)
- SIEM/SOAR + LLM hybrid systems
- Anti-hallucination techniques for LLMs in security contexts (RAG-style evidence grounding, structured prompting)
- Insider threat detection (especially multi-day pattern detection)
- Open-weight models for privacy-sensitive deployments

**What's still needed:**

- Consolidated comparison table covering 8–12 directly relevant papers
- Per-paper notes on: dataset, approach, metrics, gap our work fills
- Format the table to match the term paper guideline ("Survey on related works… should have a table comparing all the works")

---

## 6. Target Paper Format (Term Paper Guidelines)

| Requirement | Rule |
|---|---|
| Template | IEEE/ACM (double column) **or** LNCS Springer (single column) |
| Sections | Abstract → Introduction (with **Our Contribution** subsection in bullets + comparison table) → Background → Survey on Related Works (with comparison table) → Future Directions → Conclusion → References |
| Comparison tables | Required: one in Intro (us vs related work), one in Survey section (per subsection if subdivided) |
| Submission | Zipped: PDF + source files (docx/latex + pptx figures) + presentation slides |
| Presentation | 15 min total (10 talk + 5 Q&A), each group member must present |

---

## 7. Can This Be Published in IEEE? — Honest Assessment

**Short answer:** As a course term paper, yes, the deliverable is on track. As a published IEEE paper, it depends heavily on the venue tier.

### IEEE-tier breakdown

**Top-tier (IEEE S&P, IEEE TIFS, IEEE TDSC):** Not without significant additional work. These venues expect:
- Real-world or large-scale datasets, not 15 synthetic scenarios
- Multi-model comparison (Qwen vs LLaMA vs Mistral, ideally vs GPT-4 baseline)
- Statistical significance testing across many runs
- Stronger novelty claim — LLM-assisted forensics is a hot area in 2025–2026 with rapidly accumulating prior work
- Likely a red-team or industry partnership for validation

**Workshop / mid-tier IEEE conference (IEEE CloudCom, IEEE Big Data Security workshops, IEEE DSC, IEEE Cloud Summit):** Yes, with moderate polish. The current work is competitive at this tier because:
- Hybrid rule+LLM architecture is a current research thread
- Anti-hallucination measurement is a credible contribution
- 15 scenarios with negative findings (S14, S15) is more rigorous than many submissions at this tier
- Open-weight + privacy framing aligns with industry interest

**Adjacent strong venues (non-IEEE but reputable):** ARES, SecureComm, ESORICS workshops, USENIX Security workshops — all plausible with the same level of polish needed for IEEE workshops.

### What would push it from "term paper" to "publishable workshop paper"

1. **Real log data** — even one anonymized organizational dataset, or a public dataset like LANL's authentication graph or DARPA OpTC, would dramatically strengthen the empirical claim.
2. **Multi-model comparison** — Qwen 3.5 vs at least one other open-weight model (LLaMA 3.1, Mistral, Phi-4) to show the contribution isn't model-specific.
3. **Manual narrative review** — currently flagged as "not done." Have 2–3 security practitioners rate LLM vs rule narratives on usefulness; even N=3 with inter-rater agreement is publishable.
4. **Tighten the related-work section** — the current `Paper8_LitReview` is one paper; need 8–12 cited works minimum with a real comparison table.
5. **Threat model section** — current writeup lacks an explicit adversary model. Workshop reviewers will flag this.
6. **Reproducibility artifact** — the code is already open-source-ready; one polished GitHub release with seed data would tick the artifact-evaluation box.

### Honest verdict

- **Course submission:** ready or near-ready. Main gap is the term paper document itself.
- **Workshop paper at IEEE CloudCom / Big Data Security / ARES:** 4–6 weeks of focused work away.
- **Top-tier journal/conference:** 6–12 months and probably real-world data. Not feasible in current term scope.

---

## 8. Plan And What Remains

### What's done (from `IMPLEMENTATION_STATUS.md`)

- All 5 build phases complete (foundation → core engine → LLM → evaluation → polish)
- 15 scenarios, 12 rules, 7 log types, 10+ metrics
- Real LLM evaluation completed
- Stress tests across 4 dimensions executed
- 47 pytest tests passing
- Docker stack working
- Streamlit dashboard live
- FastAPI + Laravel APIs functional

### What remains for the term paper deliverable

| Item | Status | Effort |
|---|---|---|
| Term paper document (IEEE/ACM or LNCS) | Not started | 2–4 days |
| Introduction with "Our Contribution" bullets + comparison table | Not started | Half day |
| Background section (private cloud forensics, LLM forensics, threat model) | Not started | 1 day |
| Survey on related works (8–12 papers, comparison table) | One paper drafted (`Paper8_LitReview_Writeup`) | 1–2 days to expand |
| Methodology section (architecture + scenarios + rules + LLM + evaluation) | Source material in `IMPLEMENTATION_STATUS.md` and `MASTER_PROMPT.md` | 1 day |
| Results section (filled comparison table from real runs) | Data ready | Half day |
| Discussion / Future Directions (S14 misdirection, S15 amplification, multi-model, real data) | Source material in status doc | Half day |
| Conclusion | — | 2 hours |
| References (BibTeX or .bib file) | Need to build | 1 day |
| Final presentation slides (15 min, all members) | `Project_Presentation.pptx` exists, needs tightening | 1 day |
| Zipped submission package | — | 1 hour |

### Scenario Hierarchy (Decided)

The proposal commits to 4 scenarios; the implementation has 15. The paper uses a two-tier structure:

**Primary evaluation (matches proposal):**
- S1 Normal baseline
- S2 Noisy benign (conference travel)
- S3 Obvious external attack
- S4 Slow multi-day insider

**Extended evaluation (robustness + failure characterization):**
- S5–S13 — additional scenarios across hijack, maintenance, failed stuffing, full-infrastructure attack, etc.
- S14 — decoy misdirection (LLM fooled by noisy decoy, missed the quiet real attacker)
- S15 — rule-context amplification (LLM amplified rule false positives into an incorrect verdict)

S14 and S15 are kept **as documented failure cases**, not hidden. They make the work more credible and feed directly into the Discussion section.

### Synthetic-Data Limitation (Must Be Stated Explicitly)

Reviewers will attack the synthetic-scenario basis. The paper must openly say:

> This study evaluates controlled forensic scenarios with predetermined ground truth rather than real-world enterprise logs. The purpose is to isolate reasoning behavior, hallucination risk, and rule-vs-LLM failure modes under known ground truth — not to claim production-grade detection performance. Real-world validation is identified as future work.

### Future Directions section content (already in hand)

- Real-world dataset validation (LANL, DARPA OpTC, or anonymized industry)
- Multi-model comparison (Qwen vs LLaMA vs Mistral vs Phi-4)
- Manual narrative usefulness scoring with security practitioners
- On-premises deployment with vLLM/Ollama (architecture supports it; need to validate)
- Adversarial robustness — S14 misdirection shows decoy attacks fool the LLM; future work on multi-suspect reasoning
- Streaming / continuous-mode operation (currently batch)
- Multi-tenant deployment
- Adapter library for vendor log formats (rsyslog, CEF, ESXi hostd, nginx, PostgreSQL)

---

## 9. Writing Order And Immediate Deliverables

Engineering is mostly done. The main risk now is **overclaiming**, not implementation. Claims must stay narrow, evidence-grounded, and brutally honest about synthetic data and failure modes.

**Writing order:** Methodology and Results first (concrete, already supported by data), *then* Introduction and Abstract (which become much easier once the spine is written).

### Immediate Deliverables (in order)

1. **Final paper outline** — section-by-section skeleton with bullet-level content per section.
2. **Related-work comparison table** — 8–12 directly relevant papers across LLM-for-SOC, cloud forensics, anti-hallucination, insider threat.
3. **Intro contribution table** — our work vs prior work, axis-by-axis.
4. **Methodology diagram** — pipeline figure (raw logs → parser → normalizer → OCSF/ECS → timeline → correlation → rules + LLM → validator → evaluation).
5. **Results table and failure-case discussion** — primary 4 + extended 11, with S14 and S15 as documented failures.

## 10. Bottom Line

A working research prototype with a real empirical comparison: rules 60% vs LLM 93% verdict accuracy across 15 controlled scenarios, with no invalid event-ID citations under the validator and two documented failure modes that strengthen rather than weaken the paper.

The course deliverable is reachable in 1–2 weeks of focused writing. A workshop-grade version is 4–6 weeks away, gated by lit review depth and ideally a multi-model comparison run.
