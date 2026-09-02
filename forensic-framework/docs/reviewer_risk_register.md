# Reviewer Risk Register

This is an internal scientific challenge list, not rebuttal language. A concern
is closed only by evidence in the frozen artifact or an explicit narrowing of
the claim.

| Likely concern | Why it matters | Current evidence or mitigation | Remaining gate |
|---|---|---|---|
| The benchmark is synthetic and too easy | Perfect rules can make a detector paper tautological | The paper states that tuned rules reach 100% and positions the contribution as claim-evidence warrant measurement, not detection accuracy | Do not generalize incident prevalence or autonomous detection performance |
| The evaluator validates its own authored ontology | Mechanical rules can encode author expectations and systematic errors | Two independent blinded DFIR reviews, third-reviewer adjudication, per-axis confusion, weighted agreement, and a human-labeled primary estimator are implemented | Obtain real qualified reviewers and institutional approval |
| Abstention wins by refusing everything | A zero-exposure policy may have zero utility | Every safety estimate is reported with coverage, attack recall, verdict accuracy, and a fixed 3-point non-inferiority margin | Preserve an unfavorable joint result if the margin fails |
| Variants and repetitions inflate sample size | Treating 360 variants or 5,400 records as independent would produce invalid precision | Base case is the fixed independent unit; variants and repetitions are averaged within base case; bootstrap resamples complete clusters | Retain the 36-case limitation prominently |
| Human claim sampling ignores delivery policy | Agreement alone would not validate H1 | Analysis v1.2 joins adjudicated sampled claims to every frozen record sharing the generator hash, applies delivery, weights strata, and bootstraps claims and base cases | Report achieved interval width and effective sampled claims |
| Post-start analysis choices permit outcome tuning | Several estimators were not fully operationalized before inference | Append-only deviation log distinguishes the pre-test H1/H2 estimands from exploratory H3/H4 and untestable H5; no corrected-run aggregate outcome informed the human estimator | Avoid confirmatory language for H3--H5 and do not call the study preregistered |
| The original holdout leaked mutation roles | Visible `decoy`, `noise`, and attack/benign names could make results meaningless | The leaky partial run is excluded with hashes and record counts disclosed; corrected identifiers are opaque and corpus-wide leakage tests pass | Keep the invalidation visible in the main paper and artifact history |
| One revision-opaque model cannot support an “LLMs” claim | Model behavior can be checkpoint- and provider-specific | Endpoint hash, alias, served family label, runtime, prompt hashes, and missing digest are disclosed; claims are scoped to one deployment | Add independent providers only if exact access is supplied before a new frozen run |
| External CERT labels are not visible-evidence warrant labels | An answer-key insider label cannot validate proposition-level attribution after downsampling | External results separate latent answer-key detection from mechanical visible-record warrant; the paper calls the transfer test schema/operational evidence | Never call CERT answer keys expert warrant ground truth |
| Closest work already studies evidence attribution | FORCEBENCH and attribution benchmarks challenge broad novelty claims | Novelty map cites FORCEBENCH, AttributionBench, RECV, AuditBench, SIR-Bench, SecRespond, and LogInject; contribution is forensic axis decomposition plus paired context/evidence mutations and policy exposure | Recheck literature and priority language immediately before submission |
| Raw outputs or artifact metadata deanonymize authors | Double-blind violations can cause desk rejection | Explicit allowlist, deterministic archive, source-path/identity/secret scan, PDF metadata extraction, and non-tracking artifact policy are tested | Run the final scan from a clean commit and manually inspect every PDF page |
| Expert review creates an undisclosed human-participant burden | Consent, compensation, identity, and timing require governance | Preflight gate, unapproved consent template, offline no-network UI, opaque IDs, active-visible timing, data minimization, and separate private records are documented | Institutional determination and approved consent/compensation are mandatory |
| A conference deadline may pressure overclaiming | An incomplete paper can harm credibility more than a later submission | USENIX Security 2027 Cycle 2 is primary; DFC Europe 2027 is considered only if all evidence gates close | Do not submit the proxy-only draft to meet September deadlines |

## Release decision

A paper may be called submission-ready only when the corrected and external
runs are complete, expert annotation is adjudicated and checksum-bound, the
human-primary estimate is generated, all claims are reconciled with that
estimate, the anonymous artifact passes a clean-environment reproduction, and
human authors approve the final text, authorship, ethics statement, and
release license.
