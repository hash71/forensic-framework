# Public Validation-Source Audit

Audit date: 2026-09-03

Purpose: determine whether an existing public benchmark can independently
validate WarrantLab's claim-level mechanical warrant labels without collecting
the planned DFIR-expert annotations.

## Result

No located public benchmark can replace the frozen WarrantLab human-validation
study. The closest available evidence is useful in two narrower ways:

1. **SecRespond provides external construct triangulation.** Its public,
   security-expert-designed post-compromise checklists independently separate
   discovery, evidence, and attribution, and sometimes require uncertainty,
   counterevidence, or the rejection of fabricated entry points. This supports
   WarrantLab's decision to evaluate evidence and attribution separately.
2. **FORCEBENCH provides cross-domain warrant triangulation.** Its adjudicated
   claim--passage pairs directly test whether fixed evidence licenses stronger
   wording. This supports the evidence-force construct outside forensics.

Neither source labels WarrantLab's frozen claims, applies WarrantLab's twelve
semantic axes to the visible event record, or estimates errors in WarrantLab's
authored mechanical proxy. The three-role Gemma panel remains an exploratory
sensitivity analysis for the same reason. The requirement for two independent
qualified DFIR reviewers and blinded third-reviewer adjudication therefore
remains unchanged.

## Candidate audit

| Candidate | Human or expert evidence in the primary source | Availability checked on the audit date | What it can establish here | Why it cannot replace WarrantLab review |
|---|---|---|---|---|
| [SIR-Bench](https://arxiv.org/abs/2604.12040) | Five security engineers with 3--8 years of incident-response experience; one labels and a second reviews each case; about 8% are discussed; triage agreement is 94.2% with $\kappa=0.87$; expected findings link to CloudTrail event IDs, ARNs, and times | The paper says the 794 cases and OUAT framework are planned for public release but gives no security SIR-Bench data/code locator | Strong domain and evidence-linking precedent | Labels expected findings and triage, not every material field and force of an atomic WarrantLab claim; the data were not executable from the primary release record |
| [AuditBench](https://arxiv.org/abs/2606.10281) | Detailed labels are described as manually verified; two authors check a 30-pair sample of the LLM explanation judge | The submission appendix exposes one representative scenario for each of four tasks at an anonymous artifact URL; that endpoint required authentication during this audit, and the paper says the full code/data release is future work | Strong audit-log task and field-level precedent | The available submission subset is too small and its explanation score is entailment against attack descriptions, not visible-evidence warrant on WarrantLab claims |
| [FORCEBENCH](https://arxiv.org/abs/2605.28044) | All 433 candidates are independently reviewed by two research assistants and adjudicated; 283 are accepted; pre-adjudication $\kappa=0.78$; the headline set retains 198 local force contrasts | The paper states that data, prompts, and outputs are released, but its arXiv source materials provide no usable release locator or data payload | Direct human-adjudicated support for the claim that relevant evidence can under-warrant stronger wording | The unit is a general cited-text claim--passage pair, not a forensic report grounded in event records; it does not label WarrantLab outputs |
| [SecRespond](https://arxiv.org/abs/2607.26791) | Security experts manually design 280 checkpoints and audit key range-construction stages; three LLM judges score reports; one security expert, blind to judge results, rescores 10 trajectories for each of 60 checkpoints (600 checkpoint--trajectory ratings), yielding Pearson $r=0.96$, quadratic-weighted $\kappa=0.94$, and MAE 0.15 | Public at the [official GitHub tree](https://github.com/Alibaba-NLP/qqr/tree/main/data/secrespond) and [Hugging Face dataset](https://huggingface.co/datasets/Alibaba-NLP/SecRespond); audited Git commit `0ce64b49e732e2b5515a9f90850c904b2254acb1` | Independent, domain-specific construct triangulation for separating discovery, evidence, attribution, and response planning | Its checklists encode known range findings and judge complete SecRespond reports. They do not apply WarrantLab's axes to WarrantLab claims, and one expert's judge-agreement sample is not an independent reference standard for this study |

## Reproducible SecRespond structure check

The public lightweight GitHub tree was inspected without downloading the range
disk archives. At the pinned commit it contains ten English checklist files and
280 `CHK` headings in total. Every checkpoint has a detection-score field. The
checklists define detection as discovery plus evidence plus attribution, though
some newer files express the three criteria inline rather than on separate
lines. Seven checkpoints are directly tagged `Q-04` (honesty and confidence
calibration); additional checkpoints also prohibit fabricated CVEs, require
uncertainty, or require ruling out alternatives.

The structural count can be repeated from a checkout of the pinned commit:

```bash
git clone --filter=blob:none --no-checkout https://github.com/Alibaba-NLP/qqr.git
git -C qqr sparse-checkout init --cone
git -C qqr sparse-checkout set data/secrespond
git -C qqr checkout 0ce64b49e732e2b5515a9f90850c904b2254acb1
find qqr/data/secrespond/ranges -name checklist.en.md -exec \
  rg -c '^#{3,4} CHK-[0-9]+' {} + | awk -F: '{total += $NF} END {print total}'
```

Expected output: `280`.

SecRespond's files are licensed CC BY-NC-SA 4.0. No checklist text or disk
artifact is copied into WarrantLab; the audit records only bibliographic facts,
the public commit, and aggregate structural observations.

## Decision rule for future substitutions

A public source can replace the planned human review only if it provides, for
the same frozen WarrantLab claim population or a predeclared probability sample
from it:

- labels made from the visible evidence rather than latent incident truth;
- supported, contradicted, insufficient, or not-applicable labels for every
  applicable WarrantLab axis;
- decisive-materiality labels;
- two qualified independent DFIR reviewers plus blinded adjudication;
- item-level labels and provenance that can be checksum-bound to the analysis;
  and
- license and ethics terms compatible with the anonymous artifact.

None of the audited candidates meets these substitution criteria.
