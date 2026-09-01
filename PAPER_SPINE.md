# Paper Spine — Authoritative Outline

This document is the agreed-upon paper structure. All section drafts must conform to this spine. Do not change the framing, claim boundaries, or section order without revising this file first.

---

## Title

**Augmenting Rule-Based Private-Cloud Forensic Investigation with Evidence-Grounded LLM Reasoning**

Possible subtitle: *A Controlled Comparison of Rule-Based and LLM-Assisted Post-Incident Triage Under Citation Constraints*

Avoid "privacy-preserving" in the title. That is deployment context, not the main contribution.

---

## The One Claim We Defend Hard

> In controlled private-cloud forensic scenarios with known ground truth, an evidence-grounded open-weight LLM improved scenario-level triage accuracy over a rule-only baseline while producing zero invalid event-ID citations under the implemented validator.

### Claims We Do NOT Make

- "LLMs detect insider threats"
- "Hallucination-free investigation"
- "Production-ready private-cloud IDS"
- "Privacy-preserving forensic AI" as the main novelty
- "Generalizes to real enterprise logs" (without evidence)

---

## Abstract (Content Targets)

1. Private-cloud forensic investigation lacks unified audit services like CloudTrail.
2. Rule-based triage is explainable but brittle.
3. LLMs can reason across weak evidence chains, but hallucination risk is unacceptable in forensics.
4. This work evaluates a constrained LLM layer over normalized forensic events.
5. Across 15 controlled scenarios, rules achieved 60% verdict accuracy while the LLM achieved 93%.
6. The validator recorded zero invalid event-ID citations.
7. Two failure cases show limits: decoy misdirection and rule-context amplification.
8. The study is synthetic and intended to isolate reasoning behavior, not claim production-grade detection.

Use the phrase **"improves post-incident forensic classification and explanation"** — not "detects insider threats."

---

## 1. Introduction

### 1.1 Problem Context
- Private clouds in banks, government, regulated organizations.
- No single audit plane equivalent to CloudTrail/GuardDuty.
- Evidence spread across: authentication, file-access, admin, network, database, web-server, email logs.
- Manual reconstruction is slow and expert-dependent.

### 1.2 Limitation of Rule-Based Forensic Triage
- Rules are transparent and deterministic.
- Two failure modes:
  - **False positives** — conference travel, planned maintenance, unusual but legitimate access.
  - **False negatives / weak classification** — slow multi-day exfiltration, scope creep, low-volume insider behavior.
- Frame: rules recognize known local patterns; they are weaker at interpreting distributed evidence chains across time.

### 1.3 Why LLMs Are Attractive but Dangerous
- LLMs can synthesize weak signals across many events.
- Unsupported claims are dangerous in forensics.
- Reframed research question: *Can a constrained LLM, operating only over structured evidence and validated citations, improve scenario-level forensic triage compared with rules alone?*

### 1.4 Research Question
> Does LLM-assisted reasoning, given structured private-cloud evidence, improve post-incident forensic understanding compared with rule-based analysis alone, without introducing unacceptable evidence-citation hallucinations?

### 1.5 Contributions
1. A private-cloud forensic triage pipeline that normalizes heterogeneous logs into a unified event schema and reconstructs correlated timelines.
2. A controlled comparison between a 12-rule forensic triage engine and an evidence-grounded open-weight LLM reasoning layer.
3. A citation-validation mechanism that checks event-ID grounding, chronology, actor/entity consistency, and selected unsupported volume claims.
4. An empirical evaluation across 15 controlled scenarios, including benign noise, obvious attacks, slow insider behavior, maintenance, hijacking, decoy misdirection, and rule-context amplification.
5. A failure-mode analysis showing where LLM-assisted forensic reasoning breaks rather than hiding negative results.

### 1.6 Intro Comparison Table

| Axis | Rule-Based Triage | Unconstrained LLM | Our Evidence-Grounded LLM Layer |
|---|---|---|---|
| Input | Structured events | Raw or structured logs | Structured normalized events |
| Reasoning | Fixed rules | Free-form generation | Constrained scenario reasoning |
| Evidence grounding | Rule-matched events | Often weak | Event-ID citations required |
| Hallucination control | N/A | Usually weak | Validator checks citations and claims |
| Private-cloud fit | High | Depends on deployment | Open-weight / on-prem compatible |
| Subtle multi-day patterns | Limited | Potentially yes | Evaluated directly |
| Benign noisy scenarios | Often brittle | Potentially yes | Evaluated directly |
| Failure modes documented | Usually partial | Often hidden | S14 and S15 explicitly analyzed |

---

## 2. Background

### 2.1 Private-Cloud Forensics
Organization-controlled infrastructure. Forensic problem is not absence of logs but absence of unified, correlated, investigation-ready evidence.

### 2.2 Forensic Triage vs Real-Time Detection (MANDATORY SUBSECTION)
> This work does not propose a real-time intrusion detection system. It assumes logs have already been collected after an incident or audit trigger. The goal is post-incident triage: timeline reconstruction, evidence-chain analysis, scenario classification, and explanation.

### 2.3 Rule-Based Security Analysis
- Rule types: threshold, impossible travel, excessive downloads, after-hours, privilege misuse, failed-login bursts.
- Strengths: deterministic, explainable, auditable.
- Weaknesses: brittle thresholds, alert fatigue, weak cross-day reasoning, no semantic context.

### 2.4 LLM-Assisted Security Reasoning
- Frame LLMs as reasoning/summarization layers, not detectors.
- Useful for: connecting weak signals, explaining timelines, comparing alternative hypotheses, reducing noisy false positives.
- Risks: hallucinated evidence, causal overclaiming, overconfidence, susceptibility to decoys.

### 2.5 Evidence Grounding and Citation Validation
Validator checks (paper-side wording):

| Validator Check | Purpose |
|---|---|
| Event-ID existence | Prevent citing nonexistent evidence |
| Chronology consistency | Prevent impossible timelines |
| Actor/entity consistency | Prevent unsupported users/IPs/files |
| Volume-claim support | Prevent "large download" without matching events |
| Citation coverage | Ensure claims are tied to input evidence |
| Verdict format | Enforce machine-readable output |
| Confidence / rationale constraints | Reduce free-form overclaiming |

> The validator does not prove that the LLM's reasoning is correct. It only reduces specific evidence-grounding failures.

---

## 3. Related Work / Survey

Subsections:
- 3.1 Cloud and Private-Cloud Forensics
- 3.2 Rule-Based SIEM/SOAR and Security Analytics
- 3.3 LLMs for Security Operations and Incident Analysis
- 3.4 Hallucination Mitigation and Evidence-Grounded LLMs
- 3.5 Insider Threat and Multi-Day Behavioral Analysis

### 3.6 Related-Work Comparison Table (target shape)

| Work | Domain | Data | Method | Evaluation | Hallucination Control | Gap |
|---|---|---|---|---|---|---|
| Paper A | SOC / log analysis | Real / synthetic | LLM | Accuracy / case study | Weak / none | No strict event grounding |
| Paper B | Cloud forensics | Cloud logs | Framework | Qualitative | N/A | No LLM comparison |
| Paper C | Insider threat | CERT dataset | ML / rules | Precision/recall | N/A | No narrative reasoning |
| Paper D | LLM for IR | Alerts/logs | GPT-based | Analyst study | Prompt-only | Not private-cloud/on-prem |
| **Our work** | **Private-cloud forensic triage** | **15 controlled scenarios** | **Rules + constrained LLM** | **Verdict accuracy, F1, FP%, hallucination checks** | **Event-ID validator** | **Controlled rule-vs-LLM comparison with failure analysis** |

8–12 real papers required. Sample PDFs are NOT topical and must not be cited as related work.

---

## 4. Methodology

### 4.1 System Overview (Pipeline Figure)
```
Scenario JSON Logs
      ↓
Synthetic Log Generator
      ↓
Raw Logs from 7 Sources
      ↓
Parser
      ↓
Normalized Event Schema
      ↓
OCSF / ECS Mapping
      ↓
Timeline Reconstruction
      ↓
Correlation Engine
      ↓
 ┌───────────────┬────────────────────┐
 │ Rule Engine   │ Evidence-Grounded  │
 │ R001–R012     │ LLM Reasoning      │
 └───────────────┴────────────────────┘
      ↓
Hallucination / Evidence Validator
      ↓
Evaluation Metrics
      ↓
Report + Dashboard
```

### 4.2 Log Sources (7)
auth, file_access, admin, network, database, web_server, email — with example evidence per source.

### 4.3 Normalized Event Schema
Fields: `event_id`, `timestamp`, `actor` (user), `source_type`, `action`, `resource`, `src_ip`, `dst_ip` (where applicable), `volume` / size, `session_id`, `status`, `severity`, `metadata`, `raw_reference`.

### 4.4 Timeline and Correlation
Chronological ordering; session grouping; cross-source linking; actor-resource matching; temporal proximity; evidence-chain construction.

### 4.5 Rule Engine
12 rules (R001–R012). Categories: impossible travel / unusual IP, excessive download, after-hours, privilege misuse, failed-login burst, sensitive resource access, external transfer, multi-source correlation. Do not over-describe each rule.

### 4.6 LLM Reasoning Layer
> The LLM receives structured forensic evidence, not raw unrestricted logs. It must produce a verdict, rationale, cited evidence IDs, and confidence. The output is then validated before being accepted for evaluation.

- Qwen 3.5-27B
- Modal deployment
- Endpoint-agnostic; swappable to vLLM / Ollama / TGI
- Open-weight / on-prem feasibility

### 4.7 Anti-Hallucination Validator
Precise wording:
> The validator checks whether the model cites nonexistent events, violates event chronology, names unsupported actors/entities, or makes selected unsupported volume claims. It does not eliminate all hallucination types, especially causal overclaiming or missing alternative explanations.

### 4.8 Scenario Design (Two-Tier)

**Primary Evaluation (matches proposal):**
| Scenario | Purpose |
|---|---|
| S1 Normal baseline | Tests benign no-alert behavior |
| S2 Noisy benign travel | Tests false-positive resistance |
| S3 Obvious external attack | Tests clear attack classification |
| S4 Slow multi-day insider | Tests subtle aggregate reasoning |

**Extended Evaluation:**
- S5–S13 — additional robustness scenarios
- S14 — decoy misdirection (failure case)
- S15 — rule-context amplification (failure case)

---

## 5. Evaluation Setup

### 5.1 Metrics
| Metric | Meaning |
|---|---|
| Verdict accuracy | Correct scenario-level classification |
| Precision / recall / F1 | Evidence- or alert-level quality |
| False-positive rate | Rule/LLM over-flagging |
| Invalid event-ID citations | Grounding failure count |
| Chronology violations | Timeline inconsistency |
| Unsupported volume claims | Evidence mismatch |
| Stress-test robustness | Stability under perturbation |

### 5.2 Experimental Conditions
1. Rule engine alone
2. LLM with structured evidence (primary)
3. (Optional) LLM with raw logs
4. (Optional) LLM with rule context
5. Stress variants: event removal, noise injection, timestamp jitter, raw-log baseline

### 5.3 Dataset Limitation (MUST APPEAR)
> The scenarios are controlled and synthetic. This allows known ground truth and targeted stress testing, but does not establish production-grade detection performance on real enterprise logs.

---

## 6. Results

### 6.1 Headline Verdict Accuracy
| System | Correct | Accuracy |
|---|---|---|
| Rule Engine | 9/15 | 60% |
| LLM | 14/15 | 93% |
| Invalid event-ID citations | 0 | — |

> This is scenario-level verdict accuracy, not general detection accuracy.

### 6.2 Primary Scenario Results
4-row table: S1, S2, S3, S4 with ground truth, rule verdict, LLM verdict, interpretation.

### 6.3 Extended Scenario Results
Full 15-row table.

### 6.4 Hallucination / Grounding Results
Use precise wording. Show table by hallucination type with checked status and observed count. Causal overclaim and missing alternative explanation are discussed qualitatively.

### 6.5 Failure Cases
- **S14 Decoy Misdirection** — grounding prevents fake evidence; does not prevent wrong interpretation of real evidence.
- **S15 Rule-Context Amplification** — LLMs can inherit bias from upstream rule alerts; rule context should be treated as evidence candidate, not truth.

---

## 7. Discussion

### 7.1 What the Results Mean
Evidence-grounded LLM reasoning improved scenario-level forensic triage in controlled private-cloud scenarios, especially where context across multiple weak signals mattered.

### 7.2 What the Results Do NOT Mean
- Not real-time detection.
- Not production-grade IDS.
- Not proof of hallucination-free LLMs.
- Not validated on real enterprise logs.
- Does not replace investigators.

### 7.3 Why Rules Still Matter
> The strongest architecture is hybrid. Rules provide deterministic triggers and transparent local patterns. The LLM provides cross-event interpretation and narrative synthesis. The validator constrains the LLM's evidence use.

### 7.4 Failure-Mode Lessons
| Failure | Lesson |
|---|---|
| S14 decoy misdirection | Need multi-suspect reasoning and adversarial robustness |
| S15 rule amplification | Need calibrated rule-context handling |
| Synthetic scenarios | Need real-world validation |
| Single model | Need multi-model comparison |
| No human review study | Need analyst usefulness scoring |

### 7.5 Threats to Validity
**Internal:** Synthetic ground truth may favor designed scenario logic; rule design may influence comparison; prompt design may influence LLM behavior.
**External:** Real enterprise logs are noisier; private-cloud environments differ widely; user baselines simplified.
**Construct:** Verdict accuracy may not fully capture forensic usefulness; zero invalid citations ≠ full factual correctness.
**Reproducibility:** LLM outputs may vary across model versions; Modal-hosted endpoint replaceable but local reproducibility should be tested.

---

## 8. Future Directions
8.1 Real-world dataset validation (LANL, DARPA OpTC, anonymized organizational logs, hybrid synthetic+real replay)
8.2 Multi-model evaluation (Qwen, LLaMA, Mistral, Phi, optionally GPT-4 / Claude / Gemini as closed baselines if allowed)
8.3 Human analyst study (correctness, usefulness, evidence clarity, investigation speed, overclaiming risk)
8.4 Stronger grounding (claim-level evidence alignment, counter-hypothesis generation, confidence calibration, suspect-ranking validation)
8.5 Adversarial robustness (decoy users, planted misleading events, multi-suspect scenarios, low-and-slow attackers)
8.6 Deployment (vLLM, Ollama, TGI, air-gapped private cloud, SIEM integration, vendor log adapters)

---

## 9. Conclusion (Suggested Wording)

> This study shows that a constrained open-weight LLM can improve post-incident forensic triage over rule-based analysis alone in controlled private-cloud scenarios, particularly for subtle multi-event patterns and benign noisy activity. The evidence validator prevented invalid event-ID citations in the evaluated runs, but it did not eliminate all reasoning risks. The documented failures show that LLM-assisted forensics remains vulnerable to decoy evidence and upstream rule bias. Therefore, the appropriate role of the LLM is not autonomous detection, but bounded reasoning over structured evidence, combined with deterministic validation and human review.

---

## Writing Order

1. Methodology section
2. Results section
3. Failure-case discussion
4. Threats to validity
5. Related-work table
6. Introduction
7. Abstract
8. Conclusion

The paper will live or die on the maturity of the related-work table and the limitations section.
