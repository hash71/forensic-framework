# Simulated AI-Reviewer Sensitivity Protocol

Version: 1.0
Frozen before the full simulated-panel run: 2026-09-02

## Purpose and validity boundary

This exploratory study asks how sensitive the mechanical warrant results are
to language-model judgments produced from the same blinded claim package. It
does **not** simulate reviewer identity, professional qualifications, lived
investigative experience, institutional accountability, consent, or genuine
human independence. No output may be called an expert label, expert
adjudication, ground truth, or a replacement for the planned DFIR review.

## Frozen material

The input is the 400-claim blind sample in
`data/warrant_annotations/test_confirmatory_v1`. Models receive only the blind
item fields: opaque case and annotation IDs, visible events and baselines,
cited events, the atomic claim, and investigation context. They do not receive
the administrative key, expected incident label, mutation, condition, model
identity, mechanical warrant label, or sampling stratum.

## Panel

The strict-majority sensitivity panel has three prompt/deployment roles:

1. local Gemma-family strict-evidentiary reviewer;
2. the frozen remote Gemma-family deployment with a counterfactual-skeptic
   prompt; and
3. the same local Gemma weights with a separately seeded operational-DFIR
   prompt.

This gives prompt and serving-deployment variation, not three independent
model families. The remote deployment also generated the study reports, so
self-evaluation bias is possible. A distinct Qwen 0.6B configuration is an
optional capacity stress judge and is excluded from consensus. In a five-item
pilot it produced only three valid judgments after strict retries; this failure
is retained rather than repaired into apparent expertise.

## Judgment and operational-validity rules

Each model labels overall warrant, decision materiality, and the frozen twelve
semantic axes. Valid labels are `SUPPORTED`, `CONTRADICTED`, `INSUFFICIENT`,
and `NOT_APPLICABLE`. The runner requests JSON mode, disables hidden reasoning
on local Ollama judges, preserves the exact raw provider response, hashes
prompts and responses, records endpoint and model provenance, and rejects
missing IDs, reordering, absent axes, boolean axis answers, and invalid labels.
A narrow normalization accepts null or a list of strings in the free-text
`missing_evidence` field and records that normalization in the structured
judgment.

Invalid batches are retried twice, then recursively split to individual items.
Remaining singleton failures are reported as operational failures. They are
never assigned a label by imputation.
The remote deployment uses batches of up to eight claims. Local judges use one
claim per request because pilot batching caused cross-item ID repetition and
substantially more recovery calls.

## Analysis

The panel uses strict field-level majority. Planned outputs are:

- reviewer completeness and operational failures;
- pairwise raw and sampling-design-weighted agreement and Cohen's kappa;
- the number of items with overall, materiality, or axis disagreement;
- agreement and confusion between AI consensus and the mechanical proxy,
  described as sensitivity rather than accuracy;
- a sampling-weighted version of the primary surfaced-unsafe-claim contrast
  using AI consensus, explicitly labeled simulated; and
- a 120-item post-hoc priority list for later real review.

The priority list ranks AI disagreement, AI-versus-mechanical disagreement,
high-risk actor/authorization/intent/causality/decision axes, and generator
decisiveness. It is targeted triage, not probability sampling; expert results
on that subset cannot estimate population accuracy without a separate sampling
design.

The analysis writes `analysis.json`, `consensus.jsonl`,
`disagreements.jsonl`, and `priority_for_human_review.csv`. The derived JSONL
files make every field-level majority and disagreement directly auditable.
`prepare_targeted_human_review.py` converts the first 120 priority rows into a
new offline blind package with independently shuffled reviewer arms. The
selection basis stays in the administrative directory and is never embedded
in the reviewer interface.

## Interpretation rule

Agreement would show that the result is not unique to one authored rule set,
but it would not prove correctness because the judges can share training data,
model-family biases, prompts, and benchmark artifacts. Disagreement would
identify construct-sensitive claims and focus real review. In neither case may
the simulated endpoint replace the manuscript's human-validity gate.

## Invalidated launch

The first full-run launch was stopped after 158 valid remote judgments and no
accepted local judgments. Ollama ignored the template-level thinking flag for
one large strict-review batch and spent the 4,096-token response budget in a
separate reasoning field, returning empty content. Those partial outputs are
retained under an `invalidated-` run name. The final run starts from zero after
adding and testing Ollama's explicit `think:false` request field.

The second launch completed the remote role (400 judgments) but was stopped
with 101 strict-local and 12 operational-local judgments. Parallel local
requests sometimes returned `done:false`, and multi-item local batches repeated
or renamed annotation IDs. All such responses were rejected. The final launch
uses sequential single-item local requests; no label from either invalidated
launch is reused.
