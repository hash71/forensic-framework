# Related-Work and Novelty Map

Review date: 2026-09-02  
Scope: LLM-assisted digital forensics, SOC triage, cloud incident response,
evidence attribution, claim verification, calibration, and adversarial log
analysis. This is a living map, not a claim that every publication has been
found.

## 1. Defensible novelty boundary

The v2 study does **not** claim to be the first work to:

- apply an LLM to security logs or digital forensics;
- compare an LLM with conventional detection baselines;
- require citations or structured evidence;
- use an LLM agent for cloud incident investigation;
- evaluate CERT insider-threat data;
- study alert-context effects or prompt injection; or
- recommend human oversight.

The target contribution is narrower:

> A controlled benchmark and evaluation method for atomic forensic
> evidential warrant, using paired evidence and context mutations to separate
> citation validity from whether evidence licenses exact attribution,
> chronology, quantity, authorization, intent, causal, and decision claims;
> followed by an alert-blind verifier and a fixed abstention intervention whose
> safety--coverage trade-off is measured at one frozen operating point.

The implemented intervention is not a calibrated confidence policy. Protocol
H5 could not be tested confirmatorily because no threshold grid, selective-risk
function, or trend statistic was pre-specified; calibration remains future
work.

Any final priority claim must be rechecked immediately before submission and
phrased as `to our knowledge` with explicit comparison criteria.

## 2. Closest security and DFIR systems

| Work | Evidence and setting | What it already covers | Remaining distinction for v2 |
|---|---|---|---|
| [Audit-LLM](https://arxiv.org/abs/2408.08902) | CERT r4.2/r5.2 and PicoDomain | Multi-agent decomposition, tools, evidence-based debate, insider-threat conclusions | Atomic claim warrant and counterfactual context effects are not its primary evaluation object |
| [GenDFIR](https://arxiv.org/abs/2409.02572) | Forensic timelines | Rule-based artifact selection plus retrieval-augmented timeline reasoning | v2 evaluates exact claim-evidence relations rather than semantic enrichment alone |
| [CORTEX](https://arxiv.org/abs/2510.00311) | Production SOC investigations | Specialized agents, typed tools, linked evidence, auditable triage decisions | v2 isolates warrant errors under paired controlled mutations and measures a fixed abstention policy at one operating point |
| [Holmes](https://arxiv.org/abs/2601.14601) | Cloud-network DDoS investigation | Evidence-grounded, auditable, cost-controlled agent | Evidence-grounded cloud investigation is therefore not itself novel |
| [Retrieval-Augmented LLMs for Security Incident Analysis](https://arxiv.org/abs/2603.18196) | Multi-source logs | Targeted retrieval, MITRE ATT&CK context, attack-sequence reconstruction | v2 evaluates whether each generated proposition is warranted |
| [SIR-Bench](https://arxiv.org/abs/2604.12040) | 794 cloud incident-response cases from 129 incident patterns; five security engineers label/review expected findings linked to event IDs, resources, and times | Triage accuracy, novel finding discovery, tool appropriateness, human-aligned adversarial LLM judging | v2 makes false or over-strong cited findings, counterevidence, and claim precision primary endpoints; SIR-Bench's paper still describes public data/code release as future work |
| [AuditBench](https://arxiv.org/abs/2606.10281) | More than 50 Windows/Linux audit-log scenarios | Four investigation tasks, five frontier models, prompt and representation effects, explanation errors | v2 supplies paired causal context interventions and a forensic warrant ontology; its submission artifact lists only four representative scenarios and was not publicly retrievable during this audit |
| [SecRespond](https://arxiv.org/abs/2607.26791) | 10 public compromised cloud-host ranges, 23 models, and 280 security-expert-designed checkpoints | Separates checkpoint discovery, evidence, attribution, and planning; one blinded security expert rescored 600 checkpoint--trajectory instances for judge validation | Its separately developed decomposition triangulates the construct, but its range facts and reports do not validate v2's claim-axis labels or mechanical proxy |
| [DFIR-Metric](https://arxiv.org/abs/2505.19973) | Knowledge, CTF, and tool-testing tasks | Broad DFIR capability benchmark | v2 is an evidence-bearing incident-reasoning benchmark rather than a general knowledge test |

## 3. Evidence attribution and factuality

| Work | Key idea | Use in v2 |
|---|---|---|
| [Attribution, Citation, and Quotation survey](https://aclanthology.org/2026.acl-long.1430/) | Systematizes 134 papers and 300 evaluation metrics across a fragmented evidence-based generation literature | State citation validity, completeness, semantic warrant, and decision reliability as separate properties rather than an overloaded grounding score |
| [ALCE](https://aclanthology.org/2023.emnlp-main.398/) | Citation correctness and completeness are distinct; cited generation remains incompletely supported | Separate identifier validity, citation completeness, and semantic warrant |
| [FActScore](https://aclanthology.org/2023.emnlp-main.741/) | Decompose long-form output into atomic facts and score support | Define atomic forensic claims as the evaluation unit |
| [RAGAS](https://aclanthology.org/2024.eacl-demo.16/) | Separates context relevance, faithfulness, and answer quality | Avoid a single overloaded grounding score |
| [AttributionBench](https://aclanthology.org/2024.findings-acl.886/) | Tests whether every generated claim is fully supported and shows that automatic attribution evaluation is difficult | Require blinded expert validation before treating the mechanical warrant checker as ground truth |
| [RECV](https://aclanthology.org/2025.findings-acl.1059/) | Decomposes evidence-based claim verification into deductive and abductive reasoning types; current LLMs struggle with abduction | Distinguish forensic semantic axes and expose missing-link reasoning rather than score only a final entailment label |
| [Evidence Attribution in Fact-Checking](https://aclanthology.org/2025.naacl-long.282/) | Uses citation masking and recovery with both human and automatic attribution assessment | Treat evidence perturbation and human validation as complementary checks |
| [Verify with Caution](https://aclanthology.org/2025.findings-acl.1175/) | Automatic factuality evaluators disagree and can misestimate system error outside their calibration domains | Report expert-vs-mechanical confusion and per-axis error before using the proxy for substantive conclusions |
| [Atomic Calibration of LLMs](https://aclanthology.org/2025.findings-ijcnlp.9/) | Response-level confidence hides claim-level calibration failure | Evaluate confidence per material atomic claim |
| [Relevant Is Not Warranted / FORCEBENCH](https://arxiv.org/abs/2605.28044) | A real, relevant citation may under-warrant claim strength; paired force-raised claims reveal citation laundering | Adapt evidence-force testing to actor, authorization, intent, causality, chronology, and forensic decisions |
| [GAVEL](https://aclanthology.org/2026.findings-acl.1789/) | Binds atomic subclaims to explicit evidence units and combines multi-agent debate with deterministic citation checks on open-book fact-checking benchmarks | Evaluate forensic semantic axes under paired evidence and alert-context mutations, and measure downstream risk--coverage rather than propose a debate architecture |
| [Cited but Not Verified](https://arxiv.org/abs/2605.06635) | Link validity and relevance can remain high while factual accuracy is substantially lower | Treat citation resolution as a surface check, never a factuality result |

The v2 paper must cite FORCEBENCH prominently. The contribution is not the
general discovery of citation laundering; it is its operationalization and
controlled measurement in evidence-bearing forensic investigation.

## 4. Human factors and operational boundary

- [Integrating Large Language Models into Security Incident Response
  (SOUPS 2025)](https://www.usenix.org/conference/soups2025/presentation/kramer)
  studies 18 analysts and 50 real incidents. Autonomous summaries omitted
  critical details in 35% of cases and introduced inaccuracies in 42%, while
  collaborative use reduced effort and improved readability and consistency.
- [LLMs in the SOC](https://arxiv.org/abs/2508.18947) reports longitudinal
  analyst use concentrated in sensemaking and context rather than autonomous
  high-stakes determinations.
- [99% False Positives](https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi)
  documents why false-positive burden and meaningful alarm presentation must be
  treated as human-workflow outcomes rather than secondary accuracy details.

These studies support an analyst-assistance deployment claim. They do not
justify autonomous attribution or action.

## 5. Adversarial context

- [Indirect Prompt Injection](https://arxiv.org/abs/2302.12173) establishes the
  general risk of untrusted retrieved content steering LLM-integrated systems.
- [LogInject / Context Contamination in LLM Analysis of Network Security
  Logs](https://www.usenix.org/conference/usenixsecurity26/presentation/karanjai)
  evaluates 12,847 log entries, including 2,569 adversarial entries, across four
  attack objectives and three production models.
- [NIST Adversarial Machine Learning Taxonomy](https://www.nist.gov/publications/adversarial-machine-learning-taxonomy-and-terminology-attacks-and-mitigations)
  supplies terminology for evasion, poisoning, privacy, and misuse threats.

Prompt injection is therefore a required robustness condition, but it is not
the primary novelty claim.

## 6. Calibration, imbalance, and abstention

- [On Calibration of Modern Neural Networks](https://proceedings.mlr.press/v70/guo17a.html)
  defines confidence calibration and demonstrates common neural-network
  miscalibration.
- [On the Foundations of Noise-free Selective
  Classification](https://www.jmlr.org/papers/v11/el-yaniv10a.html) formalizes
  risk-coverage trade-offs.
- [Optimal Strategies for Reject Option
  Classifiers](https://jmlr.org/papers/v24/21-0048.html) formalizes bounded-risk
  and bounded-coverage abstention.
- [Precision–recall under imbalance](https://pmc.ncbi.nlm.nih.gov/articles/PMC4349800/)
  explains why precision and PR curves expose prevalence-sensitive operational
  behavior that accuracy can conceal.

The paper must report prevalence assumptions and must not present perfect
attack recall without its false-positive and positive-predictive-value
consequences.

## 7. Correlated experimental designs

- [Cluster bootstrap for hierarchical
  data](https://pmc.ncbi.nlm.nih.gov/articles/PMC7148287/) motivates resampling
  complete independent clusters rather than individual variants.
- [Small-sample GEE for binary clustered
  outcomes](https://pmc.ncbi.nlm.nih.gov/articles/PMC11558877/) motivates
  corrected inference when binary observations are correlated within cases.

The base case is the inferential unit. Model repetitions and counterfactual
variants are nested observations.

## 8. Public data candidates

- [CERT Insider Threat Test Dataset](https://insights.sei.cmu.edu/library/insider-threat-test-dataset/):
  synthetic background and malicious-actor data with answer keys.
- [DARPA OpTC](https://github.com/FiveDirections/OpTC-data): approximately one
  terabyte of public endpoint/network telemetry with red-team ground truth and
  documented errata.
- [Microsoft GUIDE](https://www.kaggle.com/datasets/Microsoft/microsoft-security-incident-prediction/data):
  more than 13 million evidence rows, 1.6 million alerts, and one million
  annotated incidents with TP, benign-positive, and FP triage labels.

Dataset inclusion depends on license, accessibility, a defensible investigation
unit, and whether claim-level ground truth can be constructed without leakage.
The dated, primary-source audit in
[`public_validation_source_audit.md`](public_validation_source_audit.md)
examines SIR-Bench, AuditBench, FORCEBENCH, and SecRespond against explicit
substitution criteria.  It finds that SecRespond and FORCEBENCH strengthen
construct validity, but none can replace independent annotation of the frozen
WarrantLab claims.

## 9. Venue constraints checked on 2026-09-02

- [DFC/DFRWS Europe 2027](https://dfrws.org/call-for-papers-dfc-europe-2027/):
  abstract due 2026-09-18 and full paper due 2026-09-25. This is too early for a
  properly executed v2 confirmatory study.
- [USENIX Security 2027](https://www.usenix.org/conference/usenixsecurity27/call-for-papers):
  Cycle 2 registration due 2027-01-19 and paper due 2027-01-26; 13 body pages
  and an Open Science Appendix are required. This is the ambitious target if
  experiments, expert annotation, and artifact freeze finish on schedule.
- DFRWS USA 2027 or RAID 2027 are fallback targets once their calls and dates
  are official.

Venue choice must follow evidence readiness. The study will not be shortened or
its failures hidden to meet a deadline.
