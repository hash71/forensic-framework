# Protocol Deviations and Benchmark Corrections

This log is append-only. It records changes made after the v2 protocol was
frozen and distinguishes benchmark quality assurance from confirmatory model
inference.

## 2026-09-02 — Generator 1.0.1 evidence-starvation correction

**Stage:** benchmark quality assurance, before any v2 LLM inference or expert
annotation.

**Trigger:** a transparent rule-baseline unit test found that the
`decisive_evidence_removed` variants for `credential_compromise` and
`destructive_administration` retained an unauthorized successful log-deletion
event. The event independently met the frozen incident definition, although it
was not included in the generator's `decisive_event_ids` list. Consequently,
the visible evidence still warranted `YES` while the reference label said
`INSUFFICIENT`.

**Correction:** the retained unauthorized log-deletion event was added to the
decisive set for those two families, so the evidence-starvation mutation removes
all independently decisive attack evidence. The generator version changed from
`warrant-benchmark-v1.0` to `warrant-benchmark-v1.0.1`; the corpus and manifest
checksums were regenerated.

**Information inspected:** deterministic baseline behavior only. No LLM output,
expert annotation, primary-endpoint result, or model comparison was available.

**Impact:** case counts, family counts, variants, splits, hypotheses, endpoints,
and statistical plan are unchanged. Baseline artifacts produced during the
failed quality-assurance run were discarded and regenerated.

## 2026-09-02 — Evaluator 1.1 context-aware decisive counterevidence

**Stage:** development-only prompt calibration, before held-out v2 LLM
inference or expert annotation.

**Trigger:** on `fw2_001__canonical`, generator prompt v1.1 produced exact,
fully warranted claims about explicit successful unauthorized activity. The
v1.0 abstention rule nevertheless rejected the output because three earlier
failed authentication attempts were automatically classified as decisive
counterevidence to the final incident verdict.

**Correction:** evaluator v1.1 does not classify failed attempts as
counterevidence to the final incident when another visible event explicitly
records a successful action with `metadata.authorized=false`. Earlier
authorized activity remains contextual counterevidence but is not
outcome-decisive in that situation. Without independent incident evidence, a
failed attempt or explicit authorization remains decisive counterevidence.
Explicit event-level `authorized=false` also outranks permissive user baselines.

**Impact:** benchmark records, reference labels, prompts, case splits, and the
statistical plan are unchanged. This prevents the abstention intervention from
rejecting a warranted attack by construction. The evaluator version is now
written into every run record and manifest.

## 2026-09-02 — Protocol 1.1 primary safety estimand clarification

**Stage:** after development inference and before any held-out LLM inference.
Development outcomes had been inspected; this amendment is therefore disclosed
as outcome-aware and is not described as preregistered.

**Problem:** protocol 1.0 named raw unwarranted decisive-claim rate (UDCR) as
the primary contrast between an events-plus-alerts generator and downstream
verification/abstention. A valid paired intervention must reuse the exact same
generator response; otherwise sampling variation is confounded with the review
effect. Reuse makes raw generator UDCR identical by construction, so the
original contrast cannot identify the intervention effect.

**Correction:** protocol 1.1 defines the primary safety estimand as the number
of unwarranted decisive claims actually surfaced per independent base case.
Suppressed internal claims contribute no exposure. Raw generator UDCR remains a
paired diagnostic. Coverage, attack recall, verdict accuracy, and the unchanged
3-percentage-point attack-recall noninferiority test are mandatory joint
outcomes, preventing trivial always-abstain optimization.

**Analysis discipline:** all variants and repetitions are averaged within
`base_case_id`; only base cases are resampled in the cluster bootstrap. Human
claim labels replace mechanical labels for the final confirmatory endpoint if
the planned independent annotation is completed. The held-out split remains
unseen at the time of this amendment.

## 2026-09-02 — Feasibility threshold correction

**Stage:** deterministic protocol audit before held-out LLM inference.

**Problem:** protocol 1.0 required at least 40 valid independent base cases,
but the frozen benchmark contains 48 base cases with exactly one development
base per family, leaving 36 held-out base cases. The threshold was impossible
to satisfy even with zero endpoint or parser failures.

**Correction:** the minimum is 36, equal to the complete held-out base-case
set. Endpoint and parser failures remain retained as failures rather than
excluded, so they do not silently reduce the analysis set. This correction
does not change the benchmark, model output, endpoint, or effect definition.
