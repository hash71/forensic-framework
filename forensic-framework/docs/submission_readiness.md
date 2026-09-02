# Submission Readiness

Updated: 2026-09-02

## Target

The ambitious target is **USENIX Security 2027, Cycle 2**:

- mandatory registration: 2027-01-19 (Anywhere on Earth);
- paper submission: 2027-01-26;
- artifact submission: 2027-01-29;
- at most 13 pages of body text, with unlimited references and appendices at
  initial submission;
- double-blind paper and artifact; and
- a required Open Science appendix.

Official call: <https://www.usenix.org/conference/usenixsecurity27/call-for-papers>

Venue selection follows evidence readiness. A directly aligned, time-sensitive
alternative is Digital Forensics Conference Europe 2027 (organized by DFRWS):
10-page double-blind full papers, abstract/title due 2026-09-18 AoE and final
paper due 2026-09-25 AoE. Its scope explicitly includes AI-assisted digital
forensics, cloud forensics, tool validation, triage, and event reconstruction.
We pursue that deadline only if every expert-annotation and ethics gate is
genuinely complete; otherwise USENIX Security 2027 Cycle 2 remains the target.
The study will not hide a failed non-inferiority result, count variants as
independent incidents, or describe proxy labels as expert truth to meet a
deadline. Official DFC Europe call:
<https://dfrws.org/call-for-papers-dfc-europe-2027/>.

## Scientific gates

A submission-ready claim requires all of the following:

- [x] a frozen claim schema, prompts, and evaluator;
- [x] a paired 48-base-case, 480-record benchmark with disjoint development
  and held-out splits;
- [x] transparent constant, rule, logistic-regression, and gradient-boosting
  baselines;
- [x] a paired runner that reuses one generator output across downstream
  review conditions and retains failures;
- [x] base-case-clustered bootstrap inference and a pre-specified recall
  non-inferiority margin;
- [x] raw-response provenance, hashes, manifests, and integrity checks;
- [x] a blinded, deduplicated, deterministic annotation package;
- [x] complete held-out inference over every planned variant and repetition;
- [ ] two independent DFIR annotators plus blinded adjudication;
- [ ] institutional determination, informed consent, qualified-reviewer
  screening, and professional compensation terms completed before annotation;
- [ ] validated automatic labels with agreement and label-prevalence reporting;
- [x] one frozen strong-model deployment with an explicit narrowing of all
  model-general claims because the endpoint exposes no immutable revision and
  the two planned independent frontier providers were unavailable;
- [x] an external-data stress test with a defensible user-cluster unit and
  explicit latent-answer-key semantics, reported as transfer evidence rather
  than visible-evidence warrant validation;
- [x] a selected dataset license and a redistribution audit for derived CERT
  artifacts;
- [ ] endpoint-operator terms archived before releasing raw transcripts, or
  the anonymous/public artifact built with raw transcripts omitted;
- [ ] an identity-scrubbed, non-tracking reviewer artifact frozen with the
  exact manuscript results; and
- [ ] a final independent reference, statistics, anonymity, and ethics audit.

## Current claim boundary

Until expert annotation is complete, mechanical warrant scores are proxy
outcomes. Until the remote model revision is recovered, its results describe a
single frozen deployment identified by an endpoint hash and alias, not Gemma
as a model family. Until independent providers are run, no cross-model or
frontier-model conclusion is supportable.

The publishable contribution remains useful under those constraints: a method
and benchmark for separating citation validity from exact evidential warrant,
paired measurement of alert-context sensitivity, and an evaluation of whether
verification plus abstention reduces unsafe analyst-facing claims without
collapsing coverage or attack recall.
