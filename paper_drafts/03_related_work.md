# 3. Related Work

This work sits at the intersection of five research threads: rule-based security monitoring and SIEM correlation, large language models in security operations, LLM-assisted digital forensics, retrieval-augmented and evidence-grounded generation, and behavioural insider-threat detection. Each thread has produced relevant prior art individually; what remains underexplored is a controlled forensic-triage setting in which deterministic rules and evidence-grounded LLM reasoning are evaluated side by side over the same normalised event schema, with failures separated into verdict, suspect-attribution, and citation-grounding categories. The remainder of this section reviews each thread and concludes with the gap this paper addresses.

## 3.1 Rule-Based Security Monitoring and SIEM Correlation

Rule-based correlation is the dominant industrial approach to security monitoring. SIEM and SOAR platforms encode threshold predicates and temporal correlation rules over normalised event streams, providing deterministic triggers, transparent predicate traces, and auditability — qualities that are essential in regulated environments. The well-documented cost of this approach is alert volume. Tariq et al. [1] survey alert fatigue in security operations centres and characterise it as a structural rather than incidental problem: rules tuned to minimise false negatives generate an alert volume substantially in excess of what human analysts can investigate, and the correlation layer compounds rather than relieves the problem when rule logic is poorly maintained or the underlying log streams are inconsistent. Ban et al. [2] propose an AI-assisted SIEM framework intended to suppress benign alert clusters before analyst review, using machine learning over alert metadata; the framing is adjacent to ours but does not address evidence-grounded reasoning over the underlying timeline.

Our work treats rule-based correlation as a baseline and as a source of structured evidence for the LLM, rather than as a competitor. The transparent threshold-style rule engine described in §4.5 is deliberately weaker than a tuned operational SIEM policy, so the comparison reported in §5 is against an explainable baseline of the kind operators can audit, not against the strongest possible rule configuration. The S15 contamination effect documented in §6.4 is a direct consequence of including rule output as input context to the LLM, and identifies a calibration gap not addressed in [2].

## 3.2 Large Language Models for Security Operations

The application of LLMs to security operations has emerged rapidly between 2023 and 2025. Habibzadeh et al. [3] provide a comprehensive survey of LLM use in SOCs across log analysis, triage automation, alert summarisation, and threat-hunting workflows. They observe that most published systems are evaluated on bespoke datasets with bespoke metrics, and that the field lacks shared evaluation infrastructure — a concern this paper inherits and addresses indirectly through the published, scenario-level evaluation harness described in §5.1.

Singh et al. [4] report a longitudinal empirical study of forty-five SOC analysts over ten months, capturing 3,090 LLM queries in production analytic workflows. They find that LLMs are used predominantly for sensemaking and context-building rather than for high-stakes determinations, and that analysts treat LLM output as a flexible cognitive aid rather than as an autonomous classifier. This finding is central to the deployment posture argued in §6.5: an evidence-grounded LLM is appropriate as a triage assistant whose output is reviewed by a human investigator, not as a final attribution authority. The S14 misdirection result (§5.6) reinforces the same conclusion from the failure-mode side.

## 3.3 LLMs for Digital Forensics and Incident Reconstruction

The thread closest to this paper is LLM-assisted digital forensics. Studiawan, Breitinger and Scanlon [5] propose a standardised methodology and reference dataset for LLM-based timeline analysis, modelled on the NIST Computer Forensic Tool Testing programme. Their headline empirical finding — that the same model swings dramatically in evaluated performance depending on prompt structure (BLEU 0.15 under cold prompting versus BLEU 0.95 under context-primed prompting on the same timeline) — implies that arguments about LLM forensic capability are often arguments about prompting rather than about model capability. They also flag five limitations that this paper inherits directly: context-window truncation, closed-model dependence, weak surface metrics, single-host scope, and the absence of a separate hallucination metric. Our system addresses the last of these explicitly through the validator described in §4.7, while the first four define the boundary of our claims (§6.6).

Loumachi and Ghanem [6] propose GenDFIR, a framework that combines rule-based artefact selection with retrieval-augmented LLM reasoning over digital forensic timelines. GenDFIR is the most directly comparable system in the literature: like ours, it pairs deterministic rule logic with an LLM operating over structured evidence; unlike ours, it does not separate verdict accuracy from suspect attribution and grounding integrity in evaluation, and does not explicitly characterise failure modes. Our work differs in three ways: the validator described in §4.7 enforces event-ID citation, chronology, and entity-consistency checks before LLM output is accepted; the evaluation harness reports verdict accuracy, suspect correctness, and citation-grounding integrity as separate metrics rather than collapsing them into a single accuracy number; and two failure cases (S14, S15) are kept in the corpus and analysed rather than removed.

Two further contributions complete this thread. The DFIR-Metric benchmark [7] proposes a broad evaluation dataset for LLMs in DFIR with multiple sub-tasks; it is complementary to our narrower controlled private-cloud forensic-triage scope. Yin et al. [8] survey the broader role of LLMs in digital forensics and articulate a structural reproducibility tension: LLMs are inherently probabilistic and can produce variable outputs under identical input, undermining the reproducibility expectation of forensic science. We cite this concern directly in our reproducibility threats to validity (§6.6), and constrain it operationally through low-temperature inference and the citation validator. An earlier survey-style contribution by Wickramasekara et al. [9] explores the potential of LLMs for improving forensic investigation efficiency and provides a useful early framing for the area.

## 3.4 Retrieval-Augmented Generation and Evidence-Grounded LLMs

A separate but technically central thread is retrieval-augmented generation and evidence grounding. Our system is not classical document RAG — the LLM is given structured normalised events rather than retrieved free-text documents — but the architectural pattern of supplying external evidence and requiring the model to cite it is identical, and the failure modes documented in this thread map directly onto our results.

Huang et al. [10] survey hallucination phenomena in large language models and propose a taxonomy that distinguishes input-conflicting, context-conflicting, and fact-conflicting hallucinations from intrinsic and extrinsic categories. Our checked-versus-uncovered breakdown in §5.5 is consistent with their taxonomy and makes explicit which categories the validator in §4.7 covers (event-ID existence, chronology, entity consistency, selected volume claims) and which it does not (causal overclaim, missing alternative explanation, wrong-suspect-with-grounded-evidence). Sharma [11] surveys retrieval-augmented architectures and notes the now-familiar finding that citation correctness — every cited source exists — is necessary but not sufficient for output reliability, because a model can cite real sources and still draw an unsupported conclusion. The S14 result in §5.6 is the forensic-domain instance of exactly this distinction: every cited event is real, the validator is silent, and the conclusion is wrong about which actor the cited evidence supports.

## 3.5 Insider Threat and Multi-Day Behavioural Detection

Insider-threat detection has a longer history rooted in behavioural anomaly detection over user activity logs, often evaluated against the synthetic CERT dataset. Tuor et al. [12] propose a deep-learning approach to unsupervised insider-threat detection over structured cybersecurity data streams; this and similar machine-learning baselines establish that multi-day behavioural patterns can be learned from sequence data without explicit rule encoding. More recently, the OrgForge-IT benchmark [13] proposes a verifiable synthetic dataset for evaluating LLM-based insider-threat detection; its framing — verifiable synthetic ground truth coupled with LLM evaluation — is closest to ours, although it does not separate verdict from suspect-attribution failures in the way this paper does. Our subtle-attack scenario S4 and the seven-day exfiltration scenario S13 are positioned against this thread: the rule baseline in §5.4 fails on both at the verdict level, while the LLM identifies the multi-day read-then-download pattern that defines them.

## 3.6 Gap Addressed by This Paper

Prior work has examined SIEM alert fatigue, AI-assisted SOC triage, LLM-assisted forensic analysis, and RAG-style evidence grounding. However, these strands do not fully evaluate deterministic rules and evidence-grounded LLM reasoning side by side over the same normalised forensic event schema. This paper addresses that gap by separating binary verdict accuracy, suspect and attack-chain correctness, and citation-grounding validity, showing that an LLM can improve triage accuracy while still failing through grounded but incorrect interpretation.

Table 3.1 summarises how our work positions against each thread.

**Table 3.1 — Positioning of this paper against related work threads.**

| Work area                                           | Typical approach                                                                              | Limitation for this paper's question                                                                                | How this paper differs                                                                                                                |
|-----------------------------------------------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| Rule-based SIEM correlation [1, 2]                  | Threshold predicates, temporal correlation rules, alert prioritisation via metadata           | Brittle under contextual ambiguity; alert volume hides verdict-level FP/FN behaviour; not designed for cross-time-window aggregation | Used as transparent baseline and as structured evidence input to an LLM, with rule-context contamination measured (S15)                |
| LLMs for SOC operations [3, 4]                      | Survey + empirical analyst studies; LLMs as flexible cognitive aids                            | Predominantly real-time / streaming analyst workflows; minimal evidence-grounding enforcement                       | Post-incident triage focus; explicit citation validator; failure cases preserved and analysed                                          |
| LLMs for digital forensics [5, 6, 7, 8, 9]          | Forensic timeline analysis with prompt-engineered LLMs, with or without rule pre-selection     | Grounding rarely enforced operationally; verdict / suspect / grounding failures not separated in evaluation         | Validator enforces event-ID citation and consistency; evaluation reports verdict, suspect, and grounding axes separately               |
| RAG and evidence grounding [10, 11]                 | Retrieval over documents with required source citations; hallucination taxonomy and metrics    | Citation correctness ≠ causal correctness; document-RAG framing assumes free-text evidence                          | Structured-event citation rather than document RAG; S14 demonstrates grounded-but-wrong interpretation                                |
| Insider threat / multi-day behavioural [12, 13]     | Behavioural anomaly detection on CERT or synthetic logs; recently LLM-assisted variants        | Verdict-only metrics typical; suspect attribution rarely separated from verdict accuracy                            | Two scenarios (S4, S13) explicitly target multi-day patterns rule mapping returns BENIGN on; suspect attribution scored separately      |

The novelty defended by this paper is therefore methodological rather than algorithmic: a controlled comparison between deterministic rule-based triage and evidence-grounded LLM reasoning, over the same normalised forensic event schema, with three orthogonal correctness axes — verdict, suspect, citation grounding — and with two characterised failure cases (decoy misdirection and rule-context amplification) that bound where the approach currently breaks.

---

## References (provisional)

[1] Tariq et al. *Alert Fatigue in Security Operations Centres: Research Challenges and Opportunities.* ACM Computing Surveys, 2025. DOI: 10.1145/3723158.

[2] Ban et al. *Breaking Alert Fatigue: AI-Assisted SIEM Framework for Effective Incident Response.* Applied Sciences (MDPI), 13(11):6610, 2023.

[3] A. Habibzadeh, F. Feyzi, R. Ebrahimi Atani. *Large Language Models for Security Operations Centers: A Comprehensive Survey.* arXiv:2509.10858, 2025.

[4] R. Singh, S. Tariq, F. Jalalvand, M. Baruwal Chhetri, S. Nepal, C. Paris, M. Lochner. *LLMs in the SOC: An Empirical Study of Human–AI Collaboration in Security Operations Centres.* arXiv:2508.18947, 2025.

[5] H. Studiawan, F. Breitinger, M. Scanlon. *Towards a Standardized Methodology and Dataset for Evaluating LLM-Based Digital Forensic Timeline Analysis.* Forensic Science International: Digital Investigation, 54, 2025. arXiv:2505.03100.

[6] F. K. Loumachi, M. C. Ghanem. *GenDFIR: Advancing Cyber Incident Timeline Analysis Through Retrieval Augmented Generation and Large Language Models.* arXiv:2409.02572, 2024.

[7] B. Cherif, T. Bisztray, R. A. Dubniczky, A. Aldahmani, S. Alshehhi, N. Tihanyi. *DFIR-Metric: A Benchmark Dataset for Evaluating Large Language Models in Digital Forensics and Incident Response.* arXiv:2505.19973, 2025.

[8] Z. Yin, Z. Wang, W. Xu, J. Zhuang, P. Mozumder, A. Smith, W. Zhang. *Digital Forensics in the Age of Large Language Models.* arXiv:2504.02963, 2025.

[9] A. Wickramasekara, F. Breitinger, M. Scanlon. *Exploring the Potential of Large Language Models for Improving Digital Forensic Investigation Efficiency.* Forensic Science International: Digital Investigation, 52:301859, 2025. DOI: 10.1016/j.fsidi.2024.301859. arXiv:2402.19366.

[10] Huang et al. *A Survey on Hallucination in Large Language Models: Principles, Taxonomy, Challenges, and Open Questions.* ACM Transactions on Information Systems, 2025. DOI: 10.1145/3703155.

[11] C. Sharma. *Retrieval-Augmented Generation: A Comprehensive Survey of Architectures, Enhancements, and Robustness Frontiers.* arXiv:2506.00054, 2025.

[12] A. Tuor, S. Kaplan, B. Hutchinson, N. Nichols, S. Robinson. *Deep Learning for Unsupervised Insider Threat Detection in Structured Cybersecurity Data Streams.* In Proc. AAAI Workshop on AI for Cyber Security, 2017. arXiv:1710.00811.

[13] J. Flynt. *OrgForge-IT: A Verifiable Synthetic Benchmark for LLM-Based Insider Threat Detection.* arXiv:2603.22499, 2026.

> **Citation provenance.** All thirteen references have been verified against arXiv landing pages or the publishing journal's metadata. [9] is cited preferentially via its journal publication (Forensic Science International: Digital Investigation, 52:301859, 2025; DOI 10.1016/j.fsidi.2024.301859), with the arXiv preprint retained for accessibility. [12] cites the AAAI 2017 workshop proceedings as the venue; the arXiv ID is retained for accessibility.
