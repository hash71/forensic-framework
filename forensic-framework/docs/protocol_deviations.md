# Protocol Deviations and Benchmark Corrections

This log is append-only. It records changes made after the v2 protocol was
frozen and distinguishes benchmark quality assurance from confirmatory model
inference.

## 2026-09-03 — Retrospective confidence-policy audit

**Stage:** all development and corrected held-out model outputs and aggregate
outcomes existed and had been inspected.

**Gap:** the frozen 0.65 generator-confidence threshold was described, but the
release did not quantify whether it ever rejected a valid output or whether
the underspecified `overall_confidence` score tracked verdict correctness,
exact attribution, or claim safety. The 12-case development partition was too
small and sparse to support a defensible fitted calibrator.

**Correction:** a deterministic audit now hashes both source record files,
checks disjoint base-case IDs, keeps operational failures in coverage, and
reports Brier score, fixed-width ten-bin ECE, and an explicit threshold grid
against three separately named targets. The development decision is
`not_fit`; no replacement threshold is selected. Held-out threshold rows are
marked retrospective and descriptive, with variants and repetitions remaining
nested inside 36 base cases.

**Impact:** the audit changes no prompt, output, policy decision, primary
estimand, confirmatory result, or H5 status. It exposes that the confidence gate
rejected zero valid development and held-out outputs and prevents those test
labels from being repurposed for favorable threshold tuning.

## 2026-09-02 — Human-labeled primary-estimator implementation

**Stage:** corrected held-out inference in progress; no expert labels existed.
Only run cardinality and operational-status counts from the corrected run had
been inspected, not aggregate or condition-level study outcomes.

**Gap:** protocol v1.1 already required human claim labels to replace the
mechanical proxy for the final primary safety endpoint and fixed the stratified
sample, inverse sampling-fraction weighting, unsafe-label definition,
condition contrast, and base-case inferential unit. The implementation,
however, produced only human--mechanical agreement and did not join the
adjudicated labels back to the condition-specific delivery decisions. Leaving
that gap would let expert review validate a checker without changing the
headline endpoint.

**Correction:** analysis v1.2 joins each sampled unique claim to all frozen
records sharing its case and generator-response hash, applies adjudicated
warrant and materiality labels, estimates condition-specific surfaced unsafe
claims with inverse sampling-fraction weights, and reports the pre-specified
abstention-minus-alerts contrast. A two-stage percentile bootstrap resamples
claims within annotation strata and independent base-case clusters. Tests use
synthetic labels only; no study annotation is simulated or imputed.

**Impact:** no prompt, model call, benchmark, claim sample, human label,
primary estimand, comparator, unsafe-label definition, or delivery decision is
changed. The estimator now implements the already stated human-replacement
rule. Its post-start coding time is disclosed so readers need not infer an
untouched preregistration.

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
threshold effect. The configured `calibration_split: development` records the
planned split policy; it does not imply that a calibrator was fitted. The
implemented policy uses the generator's fixed 0.65 confidence threshold plus
rule-based rejection triggers, and records but does not threshold the
verifier's self-reported confidence.

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

## 2026-09-02 — Post-result simulated AI-reviewer sensitivity study

**Stage:** after the corrected held-out and external outcomes were frozen and
after the independent expert labels remained unavailable.

**Trigger:** the authors requested an AI simulation to exercise the review
workflow and prioritize a smaller set for later real review. This analysis was
not in the confirmatory protocol and cannot validate the mechanical labels.

**Addition:** three prompt/deployment roles judge the existing 400-claim blind
sample. The simulation has its own schema, manifests, raw-response provenance,
strict operational-validity checks, consensus analysis, and explicit validity
boundary. A small Qwen judge is retained only as an operational stress pilot
after failing strict schema validity on two of five pilot claims.

**Impact:** no confirmatory hypothesis, frozen model output, mechanical score,
or human-analysis file changes. Simulated consensus is exploratory sensitivity
evidence and post-hoc triage. It is never described as expert annotation,
adjudication, or ground truth.

**Invalidated launch:** the first full simulation was stopped with 158 valid
remote judgments and zero accepted local judgments after Ollama consumed the
local response budget in a hidden reasoning field and emitted empty content.
The partial run is retained under an `invalidated-` name. No label from it is
used; the final run restarts after explicit `think:false` support was frozen.

**Second invalidated launch:** a clean JSON-mode launch completed 400 remote
judgments but was stopped with 101 strict-local and 12 operational-local
judgments. Concurrent local requests sometimes ended with `done:false`, while
multi-item local batches repeated or renamed opaque IDs. Strict validation
rejected those calls, but recovery was inefficient. The final configuration
uses sequential, single-item local requests and restarts every reviewer from
zero; none of the partial labels is reused.

## 2026-09-03 — Preserve unresolved three-reviewer label ties

**Stage:** after all three definitive AI-reviewer roles completed, during the
first aggregate-analysis attempt. The attempt stopped before writing an
analysis file.

**Problem:** the frozen rule required a strict field-level majority but the
implementation incorrectly assumed that three labels always imply one. With
four categorical warrant labels, all three reviewers can select different
values. The analyzer stopped with `strict-majority AI consensus is incomplete`.
No aggregate agreement, endpoint, or condition result was produced or
inspected before this correction.

**Correction:** no tie-break is introduced. Every all-different field is
retained as null in `consensus.jsonl` and enumerated in the disagreement
record. Agreement with the mechanical proxy is calculated only where the
relevant field has a majority. The consensus endpoint is a clearly labeled
complete-case sensitivity estimate requiring majority on both overall warrant
and materiality. Complete per-reviewer sensitivity endpoints are also reported
so every collected label contributes to a transparent robustness range.

**Impact:** this change prevents fabricated agreement and exposes consensus
coverage. Because unresolved complete cases can be non-random, the consensus
endpoint is not a population estimate and remains exploratory. Human
validation requirements are unchanged.
