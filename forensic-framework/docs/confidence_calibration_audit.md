# Confidence and abstention audit

## Purpose and validity boundary

The frozen verifier-plus-abstention policy rejects a shared alert-visible
generation when its self-reported `overall_confidence` is below 0.65, among
several other safety checks. The score was bounded to `[0, 1]`, but the frozen
schema and prompt did not define whether it estimates verdict correctness,
exact verdict-plus-suspect correctness, or claim-level evidential warrant.

This audit was designed after held-out outcomes existed. It is therefore a
retrospective diagnostic, not a confirmatory H5 test and not permission to tune
a replacement threshold on the test partition. Variants and repetitions are
nested within base cases; per-output metrics below are descriptive rather than
independent-sample inference.

## Reproduction

From `forensic-framework/`:

```bash
.venv/bin/python run_warrant_confidence_audit.py \
  data/warrant_runs/development-remote-fusion-gemma-v1_4 \
  data/warrant_runs/test-full-benchmark-v1_0_2-remote-fusion-gemma-v1_4-r3
```

The deterministic v1.1 output is
`data/warrant_runs/test-full-benchmark-v1_0_2-remote-fusion-gemma-v1_4-r3/confidence_audit.json`.
It records SHA-256 hashes for both source JSONL files and both run manifests,
verifies disjoint development/test base-case IDs, checks the benchmark hashes
bound by those manifests, and refuses malformed confidence values.

## Metrics

Only the `llm_events_plus_alerts` records are analyzed because every downstream
review condition reuses that generator response. Operational failures remain
in threshold-coverage denominators but have no confidence score.

For each of three named binary targets, the audit reports mean confidence,
outcome rate, Brier score, fixed-width ten-bin expected calibration error
(ECE), maximum calibration error, and non-empty reliability bins:

1. the three-way verdict is correct;
2. both verdict and required suspect attribution are correct; and
3. the record contains zero mechanically unwarranted decisive claims.

The checked threshold grid is fixed in code. Its rows report valid-output and
operational coverage, selective verdict and exact risk, the rate of records
with a mechanically unwarranted decisive claim, and mean unsafe-claim count.
No row is selected as a new operating point.

## Development adequacy decision

All 12 valid development outputs are at or above 0.85. They occupy only four
confidence values, three of which occur once. The 0.65 rule consequently
rejects zero valid development outputs. The development run is also bound to
the pre-hardening benchmark hash (`fb21e9...`), while the corrected test run is
bound to `edfd0d...`; they are not a like-for-like calibration/test pair.
Together with the undefined prediction target and only 12 independent base
cases, this is inadequate support for a fitted calibrator. The audit therefore
records `status: not_fit` and `threshold_selected: null`.

## Held-out diagnostic

The alert-visible generator has 1,080 held-out records: 1,044 valid outputs and
36 operational failures. Every valid score is between 0.70 and 1.00, so the
0.65 confidence gate again rejects zero valid outputs.

| Target | Outcome rate | Mean confidence | Brier | 10-bin ECE |
|---|---:|---:|---:|---:|
| Verdict correct | 79.6% | 89.7% | 0.157 | 10.1 pp |
| Exact verdict + suspect | 45.9% | 89.7% | 0.425 | 43.8 pp |
| Zero mechanically unsafe decisive claims | 60.9% | 89.7% | 0.322 | 29.0 pp |

At a post-hoc threshold of 0.90, operational coverage would be 79.2%, verdict
risk 10.8%, exact risk 44.4%, and the mechanically unsafe-record rate 38.4%.
At 0.95, coverage collapses to 14.5%, while exact risk remains 42.7% and the
unsafe-record rate 35.7%. These rows are examples of diagnostic operating
points, not selected thresholds.

## Interpretation

The frozen confidence threshold was behaviorally inert for every valid
development and held-out output. Gemma's score is closer to coarse verdict
correctness than to exact attribution or atomic-claim safety, but its intended
target is not defined and its safety relationship is not reliably monotone.
Calibrated abstention therefore requires a new, larger, disjoint calibration
partition generated under the same frozen benchmark version; an explicit
prediction target; claim- or axis-level scores; a pre-specified risk function
and acceptance constraint; and evaluation on a new untouched test set.
