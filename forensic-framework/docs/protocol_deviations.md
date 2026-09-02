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
