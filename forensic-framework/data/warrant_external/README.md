# CERT r4.2 External Transfer Data Card

## Purpose and claim boundary

This directory contains a deterministic external stress-test view of 40
user-month windows derived from the synthetic CERT Insider Threat Test Dataset
r4.2. It tests schema transfer, long-context handling, citation resolution,
operational failures, detection against the CERT answer key, and selective
reporting. It does **not** supply claim-level forensic-warrant ground truth.

The field `evaluation_target.label_semantics` is therefore fixed to
`latent_incident_label_not_visible_evidence_warrant`. A `YES` target means the
CERT answer key identifies a synthetic insider scenario in that user-month. It
does not mean that the downsampled records independently warrant every claim,
the attributed actor, intent, or a definitive incident verdict.

## Source, license, and attribution

- Creator: Brian Lindauer.
- Publisher: Carnegie Mellon University Software Engineering Institute.
- Source: *Insider Threat Test Dataset*, release 4.2.
- Persistent identifier: <https://doi.org/10.1184/R1/12841247.v1>
- Source page: <https://kilthub.cmu.edu/articles/dataset/12841247>
- License: Creative Commons Attribution 4.0 International (CC BY 4.0).

The JSONL file is an adapted research artifact. Redistribution must preserve
the creator and publisher attribution, DOI, a CC BY 4.0 notice and link, the
license disclaimer, and an indication that fields were selected, compacted,
and downsampled. No endorsement by Brian Lindauer, Carnegie Mellon University,
or the Software Engineering Institute is implied. The artifact-root
`THIRD_PARTY_NOTICES.md` maps these terms to every affected release path.

## Sampling frame

- 20 attack windows: one user-month from a CERT-labeled insider's active
  period, selected by seed 42 from eligible r4.2 windows.
- 20 benign windows: user-months sampled from users absent from the CERT answer
  file, with a seeded attempt to match the attack-window event-count
  distribution.
- 32 independent user clusters: repeated months for the same synthetic user
  share one `base_case_id` and must be resampled together.
- 39 windows are downsampled to 150 events; one complete attack window contains
  84 events. The upstream adapter preserves every device and file event, then
  samples remaining logon, HTTP, and email records across days.

This is a balanced case-control stress sample, not a prevalence sample. Its
accuracy and predictive values must not be interpreted as deployment rates.

## Transformation

`prepare_cert_warrant_external.py` converts the existing processed windows to
`cert_r4_2_cases.jsonl`. It retains stable event identifiers, timestamps,
source type, synthetic user, action, resource, status, and a small set of
source-specific metadata. It removes generated email/web text and long list
fields, reduces URLs to hosts, supplies no invented user baseline, and supplies
an explicitly empty alert list. It also removes normalized severity,
`source_ip` values that actually encode workstation names, and inferred
user/host/day `session_id` values. Those derived fields are not source evidence
and the last could incorrectly license a causal link in the warrant evaluator.

The transform contains only synthetic identities and activity. It does not
contain data about real people or organizations. The compact JSONL remains a
derivative of the CC BY source and is not relicensed as an original dataset.

## Reproduction and integrity

Run:

```bash
python prepare_cert_warrant_external.py
```

`cert_r4_2_manifest.json` records the source-file hashes, transform policy,
case and cluster counts, source DOI and license, and the output checksum. The
current JSONL SHA-256 is recorded in that manifest.

## Known limitations

- The attack sampling frame uses the answer key to choose active user-months.
- Downsampling can omit context needed to distinguish malicious from
  legitimate behavior.
- Benign means absent from the CERT insider answer file; it is not a human
  adjudication of every visible action.
- Empty baselines and alerts differ materially from the synthetic paired
  benchmark.
- Repeated users, balanced labels, synthetic behavior, and seed-selected
  windows limit population generalization.
- The automatic warrant checker was authored for the synthetic paired schema;
  its external claim labels remain an unvalidated mechanical proxy until
  blinded experts annotate an external sample.
