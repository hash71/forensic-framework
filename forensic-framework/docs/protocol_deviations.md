# Protocol Deviations and Benchmark Corrections

This log is append-only. It records changes made after the v2 protocol was
frozen and distinguishes benchmark quality assurance from confirmatory model
inference.

## 2026-09-02 — External CERT derived-linkage removal

**Stage:** external-adapter quality assurance, before any external-model
inference.

**Trigger:** a provenance audit found that the earlier generic CERT normalizer
constructs `session_id` by concatenating synthetic user, workstation, and day.
The warrant prompt and evaluator permit a shared source `session_id` to support
causal linkage. Retaining the constructed value would therefore give the model
and mechanical checker stronger linkage evidence than CERT r4.2 supplies.
Normalized `severity` and `source_ip` fields were also derived mappings rather
than source severity or network addresses.

**Correction:** the external warrant view omits those three fields. It retains
the source workstation under `metadata.pc`, removes free text, and records the
complete transform and checksum in the external data card and manifest.

**Impact:** no synthetic held-out prompt, record, endpoint, hypothesis, or
analysis changes. No external-model output existed when this correction was
made.

## 2026-09-02 — Secondary-hypothesis operationalization gap

**Stage:** analysis-code audit after the held-out extension began. Partial
held-out output existed and had been inspected.

**Problem:** protocol v1.0 stated H3--H5 in directional terms, but the frozen
statistics implementation contained only the H1 unsafe-exposure contrast, H2
recall non-inferiority test, and joint coverage/accuracy outcomes. It did not
specify H3's canonical comparator, H4's surfaced-error functions, or H5's
threshold grid, selective-risk function, and trend statistic.

**Correction:** the analysis now reports base-case-clustered descriptive
contrasts for (H3) the difference between misleading-alert and canonical
events-only/alert-visible verdict and actor flips, and (H4) independent
verifier minus self-review surfaced wrong-actor and contradicted-decisive-claim
exposure. Their four sign tests receive one Holm adjustment. Because these
estimators were operationalized after the run started, H3/H4 are explicitly
exploratory. H5 is marked not confirmatorily testable; one frozen operating
point and any descriptive risk--coverage figure cannot establish a monotone
threshold effect.

**Impact:** no prompt, model call, record, primary estimand, recall margin,
bootstrap unit, or H1/H2 analysis changed. This correction narrows, rather than
expands, the confirmatory claims.

## 2026-09-02 — Visible mutation-role leakage and run invalidation

**Stage:** benchmark and annotation-package audit after the held-out extension
began. Partial model output had been inspected.

**Problem:** generated decoy and noise events exposed `decoy=true` and
`irrelevant=true` metadata, their identifiers contained `decoy` or `noise`,
the prompt-injection identifier and metadata disclosed its role, and the strong
decoy alert literally called its actor a decoy. Core session identifiers also
contained `suspicious` for attack templates and `approved` for benign
templates. These strings made role recognition and some label distinctions
easier than the event semantics alone warranted.

**Correction:** benchmark generator v1.0.2 replaces role-bearing variant event
and session identifiers with deterministic opaque identifiers, removes visible
mutation-role flags, makes the decoy alert describe only the observed failed
login burst, and renames a failed-login review field to the evidence-bounded
`no_successful_login_observed`. Mutation roles remain only in hidden ground
truth. A corpus-wide regression test rejects role-bearing identifiers,
metadata keys, sessions, or alert text. The benchmark and deterministic
baselines were regenerated; the corrected corpus SHA-256 is
`edfd0dec7317684e3fec122ac2fc555fb3c7cc9c841d856d95845d9d40baa0f8`.

**Invalidated run:** the old-benchmark run was intentionally interrupted after
2,360 of 5,400 condition records and 1,861 raw responses. Its records SHA-256
is `f36946bd6ff14c7c26e6029aa026a5437b139fc28784c0545a0ae0a81c3afcaf`.
It is retained locally under an `invalidated-` directory, excluded from every
table, figure, annotation sample, and statistical analysis, and ignored by Git
to prevent accidental publication.

**Impact:** the corrected benchmark must be rerun in full. Because outputs from
the earlier form of the same base cases were inspected, the paper does not call
the corrected study preregistered or claim an untouched holdout. No prompt,
model, evaluator, hypothesis, endpoint definition, or decision rule was tuned
in response to the invalidated outputs.

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
