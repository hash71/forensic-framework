# Forensic Evidential-Warrant Study Protocol

Protocol version: 1.0  
Frozen on: 2026-09-02  
Status: prospective protocol for the v2 study; the prior 115-scenario study is pilot evidence only

## 1. Study objective

This study evaluates whether an LLM's cited log evidence warrants the exact
forensic claims and decisions that the model reports. It deliberately separates
four properties that are often collapsed under the word *grounding*:

1. **Citation validity**: every cited event identifier exists.
2. **Citation completeness**: every material claim cites its purported evidence.
3. **Evidential warrant**: the cited evidence supports the exact actor, action,
   object, time, quantity, scope, modality, authorization, intent, causal, or
   decision language used in the claim.
4. **Decision reliability**: the final verdict and attribution are correct,
   calibrated, robust to irrelevant context, and capable of abstaining when the
   available evidence is insufficient.

The study is not designed to prove that LLMs autonomously solve incident
response. It tests whether bounded LLM assistance can produce claims that a
human investigator can audit and whether an independent verifier and calibrated
abstention policy reduce dangerous overstatement.

## 2. Relationship to the pilot study

The existing corpus of 15 calibration scenarios, 100 generator-created holdout
scenarios, stored model outputs, CERT replay, ablations, and manuscript are
retained unchanged as the pilot study. Their purpose in v2 is to:

- motivate the distinction between citation existence and evidential warrant;
- provide regression cases for wrong-actor attribution, alert-context bias,
  benign false positives, format drift, and evidence starvation; and
- test backward compatibility of parsers and deterministic validators.

Pilot observations are not used to tune v2 test cases, choose the primary
endpoint, or select a favorable model. Variant-level pilot observations are not
treated as independent samples in v2 statistical inference.

## 3. Research questions

**RQ1 — Evidential warrant.** Among syntactically valid citations, how often do
the cited events support the exact material forensic claim?

**RQ2 — Context sensitivity.** Holding core evidence fixed, how often do alert
metadata, misleading actors, decoys, irrelevant events, missing evidence, or
schema drift change the verdict, suspect, or strength of a claim?

**RQ3 — Counterevidence.** How often do systems identify and correctly weigh
available evidence that contradicts their leading hypothesis?

**RQ4 — Verification and abstention.** Does an alert-blind, independent claim
verifier plus an explicit abstention policy reduce unwarranted decisive claims
without a material loss of attack recall?

**RQ5 — Operational reliability.** At realistic incident prevalence and review
coverage, what precision, calibration, selective risk, latency, and cost does
each system achieve?

## 4. Confirmatory hypotheses

The following hypotheses are fixed before v2 test-set model inference:

- **H1 (primary):** the proposed generator-verifier-abstention pipeline reduces
  the unwarranted decisive-claim rate relative to an events-plus-alerts LLM.
- **H2 (non-inferiority):** the proposed pipeline's attack recall is no more
  than 3 percentage points below the events-plus-alerts LLM.
- **H3:** misleading-alert conditions increase verdict-flip and actor-flip rates
  for the events-plus-alerts LLM relative to the events-only LLM.
- **H4:** the independent verifier reduces wrong-actor and contradicted-claim
  rates relative to generator self-review.
- **H5:** calibrated abstention reduces selective risk as coverage decreases.

All remaining analyses are exploratory and will be labeled as such.

## 5. Units, populations, and split policy

### 5.1 Independent unit

The independent experimental unit is a **base case**, not a generated variant,
prompt, model response, or sampling repetition. All variants, prompt conditions,
models, and repeated generations derived from one base case form a correlated
cluster.

### 5.2 Planned benchmark

The synthetic benchmark contains 48 independent base cases: four independently
parameterized cases from each of 12 families. Families cover both attacks and
legitimate-but-suspicious activity. Each base case is rendered into paired
counterfactual variants under a committed seed.

Planned attack families:

- credential compromise;
- session hijacking;
- staged data exfiltration;
- privilege abuse;
- destructive administration; and
- exposed cloud/API credentials.

Planned benign or ambiguous families:

- authorized maintenance;
- international travel;
- scheduled backup;
- quarter-end reporting;
- security testing; and
- failed credential stuffing without successful access.

### 5.3 Counterfactual variants

Each base case will include, where logically applicable:

- canonical evidence and correct alert context;
- no alert context;
- an alert naming the wrong actor;
- an alert with misleading severity;
- a strong but irrelevant decoy trail;
- counterevidence removed;
- decisive evidence removed;
- irrelevant event noise;
- schema drift; and
- passive prompt injection in an untrusted log field as a secondary robustness
  condition.

The generator records which event identifiers are decisive, exculpatory,
irrelevant, decoys, and adversarial. It also records both the latent incident
label and the verdict warranted by the visible evidence. Removing decisive
evidence may therefore change the warranted verdict to `INSUFFICIENT` without
changing the hidden fact that an attack occurred.

### 5.4 Leakage prevention

- All variants of one base case remain in the same split.
- Test-family templates and base-case seeds are frozen before test inference.
- Prompt development uses pilot data and a disjoint development partition.
- Test outputs are append-only. Failed calls remain in the manifest and are not
  silently rerun or excluded.
- Results are reported both by base case and by family.

### 5.5 External validation

The planned external validation order is:

1. complete, predetermined CERT r4.2/r5.2 user-time units;
2. PicoDomain or a license-compatible AuditBench subset if available;
3. DARPA OpTC windows constructed from its released red-team ground truth; and
4. controlled, releaseable cloud-audit replays.

External data are never used to tune the synthetic test benchmark. Dataset
limitations, sampling frames, dropped records, truncation, and licensing are
reported in a data card.

## 6. Systems and experimental conditions

### 6.1 Required baselines

1. always-attack;
2. always-benign;
3. transparent deterministic rules tuned only on development data;
4. logistic regression over fixed structured features;
5. gradient-boosted trees over the same features;
6. single LLM, events only;
7. single LLM, events plus rule alerts;
8. single LLM with self-review;
9. proposed atomic-claim generator plus independent alert-blind verifier; and
10. proposed pipeline plus calibrated abstention.

If a dependency prevents a baseline from running, the omission and reason are
recorded before inspecting test performance.

### 6.2 Model policy

The target is at least four model classes:

- one small locally deployable open-weight model;
- one stronger open-weight model;
- two frozen frontier API models from different providers.

Every run records the provider, exact model identifier, revision when exposed,
endpoint or container image digest, prompt hash, schema version, temperature,
seed when supported, maximum tokens, timestamp, latency, token counts, cost,
raw response, parser result, and error status. Results from an unidentified
alias such as `fusion-gemma` are pilot results and cannot support cross-model
v2 claims unless the serving revision is independently recovered.

### 6.3 Repetition policy

Deterministic or seedable systems run once per case-condition pair. Stochastic
systems run three independent samples per pair at the fixed study temperature.
Repetitions are nested within base case and are never counted as independent
cases.

## 7. Output contract

The v2 model output is a collection of atomic claims. Each claim contains:

- stable claim identifier;
- claim type: observation, derived fact, hypothesis, or decision;
- subject, predicate, object, time, quantity, and modality where applicable;
- one or more cited event identifiers;
- the claimed relation of those events to the claim: supports, contradicts, or
  insufficient;
- numeric confidence in `[0, 1]`; and
- whether the claim is decisive for the verdict or attribution.

The investigation output separately contains the verdict, suspect, evidence
for and against the leading hypothesis, missing evidence, alternative
hypotheses, overall confidence, and abstention decision. Free-form narrative is
derived from the structured record and is not the authoritative evaluation
object.

## 8. Annotation and reference standard

Two independent DFIR annotators label a stratified sample of material claims.
An adjudicator resolves disagreements without seeing model identity. Annotators
receive the visible case evidence, claim, and cited events, but not the hidden
generator mutation label or system condition.

The claim-sample target is 400 after deduplicating shared generator responses.
For orientation, a simple random sample of 400 has a worst-case nominal 95%
binomial half-width of approximately 4.9 percentage points. This is not treated
as the study's actual precision because unequal stratum weights, claim
clustering, prevalence, and adjudication error can widen uncertainty; the
reported two-stage design-aware intervals determine achieved precision.
Within each nonempty stratum, a fixed seed and SHA-256 keyed order provide a
reproducible pseudorandom ranking with equal planned inclusion fractions for
claims in that stratum.

Each claim receives:

- overall warrant: supported, contradicted, insufficient, or not applicable;
- axis labels for actor, action, object, time, quantity, scope, modality,
  authorization, intent, causality, and decision strength;
- materiality: decisive or non-decisive; and
- a short rationale and missing-evidence note.

Agreement is reported with raw agreement and a chance-corrected coefficient.
Because rare labels can make kappa unstable, per-label prevalence and positive
agreement are also reported. Automated judging is permitted only after
validation against the expert sample, with error reported by label and family.

## 9. Endpoints and metrics

### 9.1 Primary endpoint

**Primary safety estimand (protocol v1.1): unsafe claim exposure.** Count the
contradicted or insufficient decisive claims actually surfaced to an analyst,
then average that count over independent base cases. Claims in an internal
generator response that a review policy suppresses are not surfaced. The
confirmatory contrast is the proposed generator-verifier-abstention pipeline
versus the events-plus-alerts LLM.

**Raw generator UDCR (paired diagnostic):** the number of contradicted or
insufficient decisive claims divided by all decisive generator claims. The
alert-visible generator response is shared across the events-plus-alerts,
self-review, verifier, and verifier-plus-abstention records. Raw UDCR must
therefore be identical across those records and cannot measure a downstream
review intervention. It remains a diagnostic for generator quality.

Unsafe claim exposure is never interpreted alone. Coverage, attack recall, and
verdict accuracy are jointly reported so an always-abstain system cannot appear
useful by suppressing every claim. The 3-point attack-recall noninferiority
margin remains unchanged.

For the final human-labeled estimate, each sampled adjudicated claim is joined
back to every frozen condition record that reused its generator-response hash.
An unsafe contribution requires an adjudicated `CONTRADICTED` or
`INSUFFICIENT` overall label and adjudicated decisive materiality; whether the
claim was surfaced is determined from that condition record. Inverse
sampling-fraction weights estimate the unique-claim population. The point
estimate first normalizes record-level claim contributions within each base
case and then averages base cases. Its percentile interval uses a two-stage
bootstrap: sampled claims are resampled within annotation strata and complete
base-case clusters are resampled independently. This human-labeled estimate,
not the mechanical census, is the substantive H1 result after annotation.

### 9.2 Non-inferiority endpoint

Attack recall of the proposed pipeline compared with the events-plus-alerts
LLM, using a pre-specified margin of 3 percentage points.

### 9.3 Secondary metrics

Verdict and attribution:

- macro-F1, balanced accuracy, attack recall, benign rejection, and Matthews
  correlation coefficient;
- false-positive rate at attack recall of at least 95%;
- suspect top-1 and top-k accuracy; and
- attack-chain precision, recall, and F1.

Evidence quality:

- citation validity and citation completeness;
- claim-warrant precision, recall, and F1;
- contradicted-claim, insufficient-claim, overclaim, wrong-actor, and
  counterevidence-recall rates; and
- warrant error by semantic axis.

Robustness:

- verdict-flip and actor-flip rates under paired context changes;
- invariance to irrelevant evidence;
- sensitivity to decisive-evidence removal;
- monotonicity violations;
- prompt-injection attack success rate; and
- schema compliance, parser recovery, and format-drift rates.

Calibration and operations:

- Brier score, expected calibration error, and reliability plots;
- selective risk, coverage, and area under the risk-coverage curve;
- precision under explicitly reported deployment prevalences;
- latency, input/output tokens, estimated monetary cost, and failure rate.

## 10. Statistical analysis

- Report effect sizes with 95% confidence intervals; do not use significance
  stars as the primary interpretation.
- Resample complete base-case clusters for bootstrap intervals.
- Use a mixed-effects logistic model or small-sample-corrected GEE for binary
  outcomes, with fixed effects for system, context condition, and their
  interaction and random intercepts or clustering by base case and family.
- Use paired comparisons only at the independent base-case level.
- Control the family-wise error rate for confirmatory secondary comparisons
  with Holm's method.
- Estimate the primary effect overall and by attack/benign family, but label
  family-level estimates exploratory unless powered in advance.
- Report missing outputs and format failures as outcomes. A malformed output is
  not converted into a favorable answer by manual interpretation.
- Evaluate calibration only on a held-out calibration partition or through
  nested cross-validation; never calibrate on the final test outcomes.

## 11. Exclusions, failures, and stopping rules

- A case is excluded only for a generator or labeling defect documented before
  model outputs are inspected. The defective case identifier and reason remain
  in the manifest.
- Endpoint outages, refusals, timeouts, invalid JSON, and truncated responses
  are reported separately and included in operational-failure metrics.
- No system is dropped because it performs poorly.
- No prompt is changed after final test inference begins.
- If fewer than 36 independent held-out base cases remain valid, confirmatory claims are
  withheld and the study is reported as exploratory.
- If independent expert annotation cannot be obtained, automated warrant scores
  are explicitly labeled proxy outcomes and the strongest forensic-validity
  claim is withheld.

## 12. Reproducibility and artifact policy

The release artifact must contain:

- benchmark specification, generation code, seeds, manifests, and checksums;
- data cards and license notes;
- frozen prompts and schemas;
- exact environment lock files and container definitions;
- raw model responses and complete call metadata when licensing permits;
- parser and validator outputs;
- annotation guide, anonymized annotations, and adjudication records;
- analysis code that regenerates every table and figure; and
- a one-command smoke test plus a documented full reproduction path.

Secrets, private endpoints, personal identifiers, and restricted third-party
data are never committed. External datasets are represented by download and
verification instructions when redistribution is prohibited.

## 13. Ethics and deployment boundary

The system is evaluated as analyst assistance, not an autonomous accusation,
blocking mechanism, or disciplinary tool. Wrong attribution can harm employees;
therefore actor claims require stricter evidence than event summaries, and
abstention is a valid outcome. Adversarial log contents are treated as untrusted
data. Real organizational logs require authorization, minimization, retention
controls, and documented handling. Synthetic data are clearly labeled.

## 14. Claim discipline for the paper

The paper may claim only what the completed evidence supports. In particular:

- citation validity is never called semantic grounding;
- synthetic cases are never called real-world incidents;
- an always-positive classifier is never described as a high-recall success
  without its benign rejection, balanced accuracy, and prevalence-adjusted
  precision;
- non-significant estimates are not described as improvements;
- failure cases and malformed outputs remain in denominators; and
- novelty is stated narrowly as a contribution in forensic evidential-warrant
  measurement and controlled counterfactual evaluation, not as the first use of
  LLMs, citations, agents, or cloud logs in incident response.
