# 4. Methodology

This section describes the forensic triage pipeline used to evaluate rule-based and LLM-assisted reasoning over private-cloud evidence under identical inputs. The pipeline is deliberately simple: it ingests synthetic logs from heterogeneous sources, normalizes them into a common schema, reconstructs a correlated timeline, and submits the same structured evidence in parallel to a deterministic rule engine and a constrained open-weight LLM. Both outputs are then evaluated against predetermined ground truth, and the LLM output is additionally validated for evidence-grounding violations.

## 4.1 System Overview

The pipeline consists of nine stages, executed sequentially per scenario:

```
Scenario JSON definitions
       │
       ▼
Synthetic log generator
       │
       ▼
Raw logs (7 source types)
       │
       ▼
Source-specific parsers
       │
       ▼
Normalizer  ──►  OCSF v1.1 / ECS 8.x mapping
       │
       ▼
Timeline reconstruction
       │
       ▼
Correlation engine
       │
       ├─────────────────────────────────┐
       ▼                                 ▼
Rule engine (R001–R012)        Evidence-grounded LLM
       │                                 │
       │                                 ▼
       │                     Citation / hallucination
       │                              validator
       │                                 │
       └─────────────┬───────────────────┘
                     ▼
              Evaluation harness
                     │
                     ▼
              Report + dashboard
```

Stage boundaries produce structured JSON artefacts that are persisted to disk and reloaded by the next stage. This makes any stage independently testable, reproducible from saved intermediate state, and inspectable for failure analysis. The implementation evaluated in this paper corresponds to commit `6c7ffbc`, with rule definitions, prompt constraints, validator checks, and schema fields taken directly from the executable pipeline.

## 4.2 Log Sources

Seven log source types are ingested. The choice reflects the typical evidence surface available in self-managed private-cloud environments where no unified audit plane exists.

| Source type   | Example evidence captured |
|---------------|---------------------------|
| auth          | login, logout, login_failed (with source IP and authentication method) |
| file_access   | file_read, file_download (with resource path and size in bytes) |
| admin         | privilege_change, log_delete (with target, justification metadata) |
| network       | dns_query, firewall_allow / firewall_block, vpn_connect |
| database      | db_query, db_login, db_export, db_login_failed |
| web_server    | http_request, http_error (method, URL, status code) |
| email         | mail_sent (sender, recipients, attachments) |

Each source type retains its own raw field naming and semantics in `data/raw_logs/`, so the parser layer must explicitly map each source's idioms onto the unified schema rather than assuming homogeneous structure.

## 4.3 Normalised Event Schema

All seven source types are mapped onto a single unified event record. The schema is deliberately minimal so that rule logic and LLM reasoning operate over the same representation.

```json
{
  "event_id":   "evt_s4_001",
  "timestamp":  "2026-04-01T09:00:00+06:00",
  "source_type":"auth | file_access | admin | network | database | web_server | email",
  "user":       "user_03",
  "action":     "login | logout | file_read | file_download | privilege_change | log_delete | dns_query | ...",
  "resource":   "/data/finance/reports/",
  "source_ip":  "192.168.1.103",
  "status":     "success | failure",
  "session_id": "sess_user_03_20260401_001",
  "severity":   "info | warning | critical",
  "metadata":   { "ticket": "HR-2026-441", "justification": "Annual review preparation" }
}
```

All timestamps carry a timezone offset (UTC+6 for the modelled organisation in Dhaka, Bangladesh). Ground-truth fields used to evaluate the system are kept in a separate ground-truth file rather than the events themselves; metadata keys prefixed with an underscore are stripped during normalisation to prevent leakage of evaluation hints into either the rule engine or the LLM input. In addition to the unified schema, each event is mapped to the OCSF v1.1 and ECS 8.x representations to support interoperability with industry SIEM tooling, although the experiments in this paper use only the unified schema.

## 4.4 Timeline Reconstruction and Correlation

Normalised events are sorted chronologically and grouped along three orthogonal axes that together produce the input to both downstream analysers.

The first axis is **session grouping**: events sharing a `session_id` are collected into per-session sequences, which surfaces session-level patterns such as mid-session source-IP changes (an indicator of session hijacking) without requiring the analyser to discover sessions itself. The second axis is **per-user grouping**, used by rules that aggregate events over time windows (for example, counting failed logins within a rolling five-minute window). The third axis is **cross-source linking**, in which events that share a user and fall within a temporal proximity window are joined across source types — so that a `privilege_change` admin event and a subsequent `file_download` file-access event by the same user become a single evidence chain for rules and LLM alike.

The correlator does not attempt heuristic attack-step labelling. It produces a chronologically ordered, lightly grouped event list that preserves all original fields. This is important: the LLM reasons over the same structured data the rule engine sees, not a richer derived representation, so any improvement attributable to the LLM cannot be explained by the LLM receiving privileged input.

## 4.5 Rule Engine

The rule engine implements twelve detection rules covering the categories conventionally seen in SIEM correlation: anomalous authentication context, threshold-based volume anomalies, privilege misuse, deletion of forensic artefacts, multi-source correlation, and protocol-level indicators. Rules are declared in YAML and evaluated against the normalised event stream and per-user baselines.

| Rule  | Name                          | Severity  | Trigger condition (informal) |
|-------|-------------------------------|-----------|------------------------------|
| R001  | unusual_login_ip              | warning   | login from an IP not in the user's `normal_ips` |
| R002  | off_hours_access              | warning   | event timestamp falls outside the user's `normal_hours` |
| R003  | privilege_escalation          | critical  | any `privilege_change` action |
| R004  | bulk_download                 | critical  | more than 5 `file_download` events within a 30-minute window |
| R005  | cross_department_access       | warning   | resource directory not in the user's `normal_directories` |
| R006  | log_deletion                  | critical  | any `log_delete` action |
| R007  | failed_login_spike            | warning   | ≥ 2 login failures within a 5-minute window |
| R008  | privilege_then_download       | critical  | `privilege_change` followed by a `file_download` within 30 minutes |
| R009  | dns_tunnel_detection          | critical  | more than 20 DNS queries to the same domain within 5 minutes |
| R010  | sql_injection_attempt         | critical  | web event with status 500 whose URL contains SQL keywords |
| R011  | data_exfiltration_volume      | critical  | total outbound bytes > 100 MB within 30 minutes |
| R012  | lateral_movement              | warning   | same user authenticated against ≥ 3 server types within 30 minutes |

Each scenario yields a list of rule alerts, each tagged with the rule that fired, the severity, and the cited event identifiers. A scenario-level rule verdict is derived from the alert set using a fixed mapping (no critical alerts → no_alert; only warnings → suspicious; one or more critical alerts → attack). The mapping is intentionally simple so that the rule engine's behaviour is fully transparent and any improvement from the LLM is attributable to reasoning, not to richer rule post-processing. This baseline represents a transparent threshold-style triage engine rather than a tuned SIEM policy optimised per scenario; the comparison reported in this paper is therefore against an explainable rule baseline of the kind operators can audit, not against the strongest possible rule configuration.

## 4.6 LLM Reasoning Layer

The LLM does not see raw logs. In the headline experimental condition reported in this paper, it receives three structured artefacts: the per-user baselines, the correlated normalised timeline for the scenario, and the list of rule alerts that fired. We refer to this as the **rule-context condition**. A second **no-rule-context condition**, in which the rule-alert artefact is omitted, is run as a diagnostic ablation rather than a parallel headline experiment; it is run for S15 over five repetitions, and the canonical artefact is saved at `data/ablation/S15_no_rule_context.json` with the per-run records under the same directory (discussed in §6.5). All headline accuracy figures in this paper refer to the rule-context condition unless explicitly stated otherwise. The LLM is required to produce a forensic verdict in a fixed JSON schema covering: a binary `verdict` (`YES`, `NO`, or `INSUFFICIENT`), an explicit `incident_occurred` boolean, the most suspicious user, an ordered attack chain in which every step cites an `event_id`, separate lists of supporting and counter-evidence event identifiers, evidence gaps, and a self-rated confidence with rationale.

The system prompt enforces five strict rules: only events explicitly listed in the timeline may be reasoned over; events may not be assumed, invented, or inferred; insufficient evidence must be reported as such; every claim must reference one or more `event_id`s from the input; and every claim carries a confidence label of `HIGH`, `MEDIUM`, or `LOW`. A second block of analysis guidance disambiguates situations the rule engine handles poorly: failed-login bursts without a subsequent successful login do not constitute a breach; legitimate maintenance activity may include privilege changes, log rotation, off-hours work, and bulk file operations and should be cross-checked against role and metadata; ticket justifications can be fabricated and a multi-day read-then-download pattern across departments remains suspicious even when each individual day looks benign; and a mid-session change of source IP within a single `session_id` is a strong session-hijacking indicator.

The model used is Qwen 3.5-27B (`fusion-brain`) served through Modal as a privately controlled remote endpoint. The client is a thin HTTP wrapper over an OpenAI-compatible chat-completions API and is endpoint-agnostic. Substituting an on-premises vLLM, Ollama, or TGI deployment requires only a configuration change to the endpoint URL; the rest of the pipeline is unaffected. This is what makes the architecture compatible with private-cloud deployments where forensic data must not leave the security boundary, but in this paper privacy is treated strictly as a deployment constraint, not as a measured contribution.

## 4.7 Evidence-Grounding Validator

Every accepted LLM output is passed through a deterministic validator before it is used in evaluation. The validator does not assess whether the LLM's reasoning is correct in a forensic sense; it only enforces that LLM claims are tied to evidence actually present in the input. Seven check categories are implemented.

| Check                         | What it enforces |
|-------------------------------|------------------|
| Event reference existence     | Every `event_id` cited in the attack chain, evidence-for, or evidence-against lists exists in the scenario's normalised timeline. |
| Timeline correctness          | The attack chain's cited events appear in non-decreasing timestamp order. |
| Unsupported claim count       | Counts attack-chain steps that lack an `event_id` field, and tests whether the free-text `narrative` field contains at least one event identifier of the form `evt_*`. The check is structural, not a general assessment of every assertion in the narrative. |
| Actor reference consistency   | Any user named in the verdict, suspect field, or narrative appears in the input timeline. |
| Temporal claim validation     | Claims of the form "within X minutes" or "after Y" are checked against the actual timestamp deltas of the cited events. |
| Volume claim validation       | Claims involving file counts, total volume, or "large download" are checked against the actual size and count of cited events. |
| Entity consistency            | Files, IP addresses, and other named entities in the narrative appear in the cited events. |

The validator's remit is intentionally narrow. It catches **invalid event-ID citations**, **chronology violations**, **unsupported actor or entity references**, and **selected unsupported volume claims**. It does not address two important hallucination categories: causal overclaiming (asserting a user *intended* exfiltration, where intent is not directly verifiable from logs) and missing alternative explanations (failing to surface plausible benign accounts of the evidence). It also does not assess whether the LLM has identified the *correct* suspect, even when every cited event is real — a distinction that matters in S14, where the cited evidence is grounded but pertains to a decoy. These categories are discussed qualitatively in the Results section rather than scored automatically. The paper's main grounding claim is therefore deliberately bounded: across thirteen of fifteen scenarios the implemented validator records no invalid event-ID citations, with the remaining two scenarios each containing one stray rule-identifier reference — not "hallucination-free."

## 4.8 Scenario Design

Evaluation uses fifteen controlled scenarios with predetermined ground truth, organized in two tiers. The primary tier reproduces the four scenarios specified in the original research proposal and carries the headline narrative of the paper. The extended tier adds eleven robustness and stress scenarios, two of which are documented failure cases that we treat as findings rather than embarrassments.

**Primary evaluation.**

| Scenario | Label  | Purpose |
|----------|--------|---------|
| S1 — Normal baseline                 | BENIGN | Control. Both systems should produce no alert; establishes that the pipeline does not cry wolf. |
| S2 — Noisy benign (conference travel) | BENIGN | False-positive resistance test. A senior developer working from a foreign IP at unusual hours, with elevated download volume, but with travel context and authorized cross-project access. |
| S3 — Obvious external attack         | ATTACK | Sanity check. Compromised credentials, off-hours foreign-IP login, privilege escalation, bulk download from a confidential directory, and partial log cleanup. |
| S4 — Slow multi-day insider          | ATTACK | The key scenario. An HR specialist incrementally expands access to finance and engineering over three days, shifting from reads to downloads, with a plausible-looking ticket justification on day one. No single day exceeds rule thresholds. |

**Extended evaluation.**

S5 (session hijack with mid-session IP change), S6 (planned maintenance window with legitimate privilege changes and log rotation — the hardest false positive in the corpus), S7 (failed credential stuffing without breach), S8 (full-infrastructure attack involving SQL injection, database export, and DNS-tunnel exfiltration), and S9–S13 add further coverage of multi-server activity, delayed event arrival, and contradictory evidence.

Two scenarios are deliberately treated as failure cases for the LLM and reported as such. Because they fail along different axes, we keep them separate in all reporting:

- **S14 — Decoy misdirection (qualitative reasoning failure, not a verdict failure).** A noisy decoy user generates rule-flagging activity while a quiet real attacker performs lateral movement and source-code exfiltration in parallel. The LLM produces the verdict `YES` against an `ATTACK` ground truth — that is, the binary verdict is *correct* — but identifies the decoy as the suspect and assembles its attack chain from the decoy's events. Every event the LLM cites is real and present in the input, so the validator records no invalid citation. The failure is therefore one of suspect identification and attack-chain interpretation, not of evidence grounding.
- **S15 — Rule-context amplification (verdict failure, ablation-confirmed).** Legitimate end-of-quarter activity produces a high volume of rule alerts. In the rule-context condition, the LLM amplifies the rule signal into an incorrect `YES` verdict against a `BENIGN` ground truth. A five-run no-rule-context ablation on the same model and the same timeline returns `NO` on all five runs (canonical artefact at `data/ablation/S15_no_rule_context.json`, summary at `data/ablation/S15_ablation_summary.json`); the verdict therefore reverses on the presence of the rule-alert artefact alone, supporting the rule-context-amplification hypothesis. This is the only verdict-level failure observed across the fifteen scenarios in the headline rule-context condition.

For headline accuracy figures, the binary verdict (`YES` / `NO` / `INSUFFICIENT`) is scored against the scenario's `BENIGN` / `ATTACK` ground truth label. By that metric the LLM is correct on fourteen of fifteen scenarios (S15 is the lone failure). Suspect identification and attack-chain correctness are scored separately and are where S14 fails. Conflating these two metrics would obscure the result; the Results and Discussion sections preserve the distinction.

The two-tier structure is intentional. The primary four scenarios anchor the paper's main claim against the originally proposed scope; the extended eleven provide robustness coverage and the two documented failure cases delimit where evidence-grounded LLM reasoning still breaks.
