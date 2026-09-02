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

