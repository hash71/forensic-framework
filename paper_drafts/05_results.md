# 5. Results

## 5.1 Evaluation Setup

The evaluation comprises fifteen controlled scenarios over the unified event schema described in Methodology. Five scenarios carry the ground-truth label `BENIGN` (S1, S2, S6, S7, S15) and ten carry the label `ATTACK` (S3, S4, S5, S8, S9, S10, S11, S12, S13, S14). Both systems run against the same normalised timeline per scenario; the LLM additionally receives the rule-engine alert list as part of the rule-context condition described in §4.6.

Three families of metrics are reported. **Verdict accuracy** is the binary classification of the scenario as `BENIGN` or `ATTACK`. **Suspect and attack-chain correctness** measure whether the LLM identified the right primary actor and assembled an evidence chain consistent with the ground-truth attack steps. **Evidence-grounding integrity** counts validator violations across the seven check categories defined in §4.7. We keep the three families separate throughout, because the most important findings of the paper — S14 and S15 — fail along different axes and would be obscured if collapsed into a single accuracy number.

All figures in this section are computed by the evaluation harness from saved per-scenario LLM responses, rule-engine outputs, and validator results. Where numbers in the prose differ from values cited in earlier internal status documents, the harness's `evaluation_results.json` file is authoritative.

## 5.2 Scenario-Level Verdict Accuracy

The headline result is summarised in Table 5.1.

**Table 5.1 — Verdict accuracy across 15 scenarios.**

| System                          | Correct | Total | Accuracy |
|---------------------------------|---------|-------|----------|
| Rule engine (transparent threshold baseline) | 10      | 15    | 66.7%    |
| LLM (rule-context condition)    | 14      | 15    | **93.3%** |
| Invalid event-ID citations (validator) | 2 | 243 | 0.8% |

The rule engine produces the correct binary verdict on ten of fifteen scenarios. The five scenarios where rules fail at the verdict level are S5 (concurrent lateral movement), S6 (legitimate after-hours maintenance, where rules fire on multiple critical patterns and yield an `attack` verdict against a `BENIGN` ground truth), S10 (delayed and out-of-order events), S12 (conflicting signals), and S13 (ultra-slow exfiltration over seven days). The LLM produces the correct verdict on fourteen of fifteen scenarios; the lone verdict failure is S15 (end-of-quarter legitimate bulk activity), discussed in §5.6. In four of the five scenarios where rules fail (S5, S10, S12, S13), the LLM is correct — and on S6, the hardest false positive in the corpus, the LLM is also correct.

These numbers describe binary verdict performance only. They do not address suspect identification, attack-chain quality, or hallucination behaviour — which are reported separately below. The improvement margin over rules (≈ 27 percentage points) holds against an explicitly transparent rule baseline; a tuned operational SIEM policy would likely close part of this gap, and the paper does not claim otherwise.

## 5.3 False-Positive Reduction

False positives are counted at two granularities: at the **verdict level** (system declares an `ATTACK` on a `BENIGN` scenario) and at the **alert level** (individual rule firings on benign-scenario events). Table 5.2 reports both for the five benign scenarios.

**Table 5.2 — False positives on benign scenarios.**

| Scenario | Description                            | Rule alerts | Rule verdict (mapped) | Verdict-level FP — Rules | LLM verdict | Verdict-level FP — LLM |
|----------|----------------------------------------|-------------|------------------------|---------------------------|-------------|-------------------------|
| S1       | Normal baseline                         | 0           | BENIGN                 | No                        | NO          | No                      |
| S2       | Noisy travel (conference)               | 13          | BENIGN                 | No                        | NO          | No                      |
| S6       | After-hours maintenance                 | **33**      | ATTACK                 | **Yes**                   | NO          | No                      |
| S7       | Failed credential stuffing              | 20          | BENIGN                 | No                        | NO          | No                      |
| S15      | End-of-quarter legitimate bulk          | 10          | BENIGN                 | No                        | YES         | **Yes**                 |

Across the five benign scenarios the rule engine generates 76 alert-level false positives in aggregate — 33 of them on S6 alone. The verdict-level mapping absorbs many of these (the `suspicious` rule verdict is mapped to `BENIGN`), which is why the rule engine's verdict accuracy on benign scenarios remains four out of five despite the alert-level noise. The LLM, by contrast, generates only one verdict-level false positive (S15) and matches the ground truth on the other four benign scenarios — including S6, where the rule engine's verdict is wrong.

The most operationally relevant comparison is on S2, S6 and S7. On S2 (a senior developer travelling to a conference, with an unfamiliar IP, late-night work, elevated download volume, and authorized cross-project access) and S7 (sustained failed login attempts that never produce a successful login), rules generate enough alerts to attract analyst attention while the LLM correctly returns `NO`. On S6, rules return an outright `ATTACK` verdict; the LLM returns `NO`. These three scenarios are where the LLM's contextual reasoning over the same evidence visibly reduces analyst burden.

## 5.4 Subtle Attack Recognition

The paper's central empirical claim is that an evidence-grounded LLM, given structured private-cloud evidence, recognises attacks whose pattern is only visible in aggregate across time. The four scenarios that exercise this capability most directly are S4, S5, S10 and S13.

S4 (slow multi-day insider) is the originally-proposed key scenario. An HR specialist gradually expands access into finance and engineering across three days, shifts from reads to downloads, and produces a plausible-looking ticket on day one. The rule engine returns `attack` (driven primarily by the privilege change and cross-department access rules), so on S4 the rule engine is verdict-correct. However, the rule alert set captures only the privilege event and the cross-department reads; the downstream multi-day read-then-download pattern that constitutes the actual exfiltration is not represented in any single rule. The LLM, given the full timeline, returns `YES` and reconstructs an attack chain that names the multi-day scope-creep pattern explicitly. F1 against the ground-truth attack steps is 0.10 for the rule engine and 0.91 for the LLM on this scenario.

S5 (concurrent activity with lateral movement) involves a session-hijack pattern where the source IP changes mid-session. The rule engine fires only three alerts and yields a `suspicious` verdict, mapped to `BENIGN` — a verdict-level miss against `ATTACK` ground truth. The LLM correctly identifies the mid-session IP change and returns `YES`, with rule F1 of 0.86 and LLM F1 of 0.92.

S10 (delayed and out-of-order events) exercises whether either system tolerates timestamp disorder. The rule engine fires three alerts, yielding `suspicious` (mapped to `BENIGN`, verdict-level wrong against `ATTACK`). The LLM identifies the attack despite the disordered timeline.

S13 (ultra-slow exfiltration over seven days) is the longest-horizon attack in the corpus. Rule alerts are sparse (six in total) and their verdict maps to `BENIGN`; the LLM returns `YES`. This is the clearest example in the corpus of an attack pattern that lives entirely in cross-day aggregation rather than in any single triggering event.

These four scenarios are where the difference between the two systems is largest. On S5, S10 and S13, the rule engine is verdict-wrong; the LLM is verdict-right.

## 5.5 Evidence-Grounding Validation

Across all fifteen scenarios, the validator described in §4.7 recorded **no invalid event-ID citations in 13 of 15 scenarios**. Of 243 total event-identifier references made by the LLM across the corpus, 241 resolve to real events in the input timeline. The two exceptions occur in S10 and S13, where the LLM's `evidence_for` list includes `R005` — a rule identifier — in one position alongside otherwise valid `evt_*` references; the validator flags these as invalid event-ID citations. Chronology violations occurred in two of fifteen scenarios (S4 and S5), where the LLM ordered one attack-chain step out of timestamp sequence; the cited events were real, but the order in which they appear in the chain does not strictly follow their timestamps. Actor-reference checks recorded zero violations: every user named in a verdict, suspect field, or narrative appears in the input. Entity-consistency checks recorded one violation, in S12, where the LLM's narrative names an IP address (`192.168.1.100`) that does not appear in any cited event; the cited events themselves are real, but the IP referred to in the prose is not present in their fields. Volume- and temporal-claim checks were not exercised in any of the fifteen accepted outputs because the LLM did not phrase claims in forms that triggered those checks; we therefore neither claim nor measure their behaviour. The validator additionally records 15 unsupported claims across the corpus (one per scenario), reflecting attack-chain steps or narrative sentences that lack an explicit `evt_*` reference; these are structural artefacts of the response template rather than fabricated evidence.

Table 5.3 reports grounding results by hallucination type, distinguishing what the validator covers from what it does not.

**Table 5.3 — Grounding results by hallucination type.**

| Hallucination type                       | Validator coverage | Observed in evaluated outputs |
|------------------------------------------|--------------------|--------------------------------|
| Nonexistent event-ID citation            | Full               | 2 (S10, S13)                   |
| Chronology violation                     | Full               | 2 (S4, S5)                     |
| Unsupported actor reference              | Full               | 0                              |
| Unsupported entity reference (IP / file) | Full               | 1 (S12)                        |
| Unsupported volume claim                 | Selected fields    | Not exercised                  |
| Unsupported temporal claim               | Selected fields    | Not exercised                  |
| Unsupported attack-chain or narrative claim (missing `evt_*`) | Structural | 15 (one per scenario)  |
| Causal overclaim (e.g. asserted intent)  | Not covered        | Discussed qualitatively (§5.6) |
| Missing alternative explanation          | Not covered        | Discussed qualitatively (§5.6) |
| Wrong-suspect identification with grounded evidence | Not covered | 1 (S14, §5.6)              |

The bounded scope is the point. The validator catches the hallucination types where forensic claims must not appear out of thin air. It does not assess whether a grounded claim points to the *right* event, the *right* actor, or the *right* causal interpretation — and the S14 failure case exists precisely in that gap.

## 5.6 Failure Cases

### S14 — Decoy misdirection (qualitative reasoning failure, validator-silent)

S14 simulates two simultaneous attacks. A loud decoy compromise on user_04 generates twenty-one rule alerts: brute-force authentication, privilege escalation, and bulk downloads. Concurrently, the real attack is a quiet lateral movement against user_02, exfiltrating proprietary source code over DNS tunneling from an internal IP. The ground-truth attacker is user_02. The LLM returns the verdict `YES` against an `ATTACK` ground truth — so the binary verdict is correct — but identifies user_04 as the suspect and assembles its attack chain entirely from user_04's events. Every event the LLM cites is real and present in the timeline, so no validator check fires.

This is the most informative failure in the corpus. It separates two forms of correctness that look similar from a distance but diverge under adversarial evidence: **citation grounding** (does every cited event exist?) and **interpretive grounding** (does the cited evidence support the claim?). The implemented validator covers the first and not the second. Evidence grounding in the citation sense is necessary for forensic reasoning but not sufficient. An adversary who can place a decoy in the evidence stream can satisfy citation grounding while still misdirecting the analyser.

The lesson is that evidence-grounded LLM reasoning needs an additional layer that the present system does not implement: multi-suspect hypothesis tracking, with the LLM required to enumerate alternative actors and the evidence for and against each, before settling on a primary suspect. This is taken up in Future Directions.

### S15 — Rule-context amplification (verdict failure)

S15 simulates legitimate end-of-quarter financial activity. A finance user accesses many sensitive files in a short window because the quarterly close is in progress. The rule engine generates ten alerts, mostly on the `bulk_download` and `cross_department_access` rules, and produces a `suspicious` verdict, which the verdict mapping correctly absorbs to `BENIGN`. The LLM, however, returns `YES` against a `BENIGN` ground truth — the lone verdict-level LLM failure in the corpus.

A diagnostic ablation removes the rule-alert artefact from the LLM's input and re-runs the same scenario on the same model. Under the no-rule-context condition, the LLM returns `NO` on all five runs (canonical artefact at `data/ablation/S15_no_rule_context.json`, summary at `data/ablation/S15_ablation_summary.json`); under the rule-context condition the same model returns `YES` on all five runs (`data/ablation/S15_rule_context.json`). The verdict therefore reverses unanimously on the presence of the rule-alert artefact alone. The natural reading is that, in the rule-context condition, the LLM treats the rule alerts as quasi-ground-truth signals rather than as candidate evidence to be weighed; ten alerts, even when individually weak, push the model's posterior toward `ATTACK` enough to flip the verdict.

This characterizes a contamination effect rather than a property of the underlying model. It also implies an architectural recommendation that the rest of the literature on hybrid SIEM/LLM systems should attend to: rule output presented to an LLM is not neutral context. It is suggestive context, and on weakly-supported alerts it can override the model's own reading of the timeline. Calibrated rule-context handling — for example, including rule alerts only with explicit confidence weights, or asking the LLM to score the rule alerts before asking it to render a verdict — is a clear next step.

### Causal overclaim and missing alternative explanations

The validator does not check causal overclaiming. Manual inspection of the fifteen attack-scenario narratives finds occasional sentences asserting user *intent* (e.g. "the user planned to exfiltrate") that the timeline cannot directly support. These remain a known gap. Similarly, on benign-mapped scenarios the LLM does not reliably enumerate alternative benign explanations even when its verdict is correct; on S15 in the rule-context condition, the absence of an explicit "this could be quarterly close activity" hypothesis is part of why the wrong verdict was reached.

## 5.7 Summary of Findings

**Table 5.4 — Findings tied to evidence.**

| Finding | Supporting scenarios | Evidence in this section |
|---------|----------------------|--------------------------|
| LLM achieves higher verdict accuracy than transparent rule baseline | 14/15 vs 10/15 across all scenarios | §5.2 |
| LLM correctly handles benign-but-noisy activity that produces large rule alert volume | S2, S6, S7 | §5.3 |
| LLM recognises subtle multi-day or cross-time-window attacks where rule mapping returns BENIGN | S5, S10, S13 (and richer narrative on S4) | §5.4 |
| LLM produces no invalid event-ID citations in 13 of 15 scenarios; the remaining two (S10, S13) each contain one stray rule-identifier reference | 13 of 15 | §5.5 |
| Citation grounding is necessary but not sufficient: the LLM can be misdirected by adversarial decoys whose events are real | S14 | §5.6 |
| Rule output is not neutral context to the LLM; weak alerts may amplify into incorrect attack verdicts | S15 (no-rule-context ablation, 5/5 runs return `NO`, reverses verdict unanimously) | §5.6 |
| Causal overclaim and missing-alternative-explanation are uncovered hallucination categories | Qualitative across attack scenarios | §5.6 |

The defended claim, restated against the evidence above:

> In controlled private-cloud forensic scenarios with known ground truth, an evidence-grounded open-weight LLM improved scenario-level verdict accuracy from 10/15 (66.7%) to 14/15 (93.3%) over a transparent threshold-based rule baseline, while producing no invalid event-ID citations in 13 of 15 scenarios under the implemented validator (two scenarios contain one stray rule-identifier reference each, out of 243 total event-identifier references). The improvement is concentrated on subtle multi-day attacks and on benign-but-noisy scenarios. Two characterised failure modes — adversarial decoy misdirection (S14, suspect-level rather than verdict-level) and rule-context amplification (S15, the lone verdict failure, in which a five-run no-rule-context ablation reverses the verdict to `NO` on all five runs) — bound where the approach currently breaks.
