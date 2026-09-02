# Forensic Warrant Benchmark v1

This directory contains the generated benchmark for the v2 forensic
evidential-warrant study. It is synthetic and must not be described as observed
production activity.

## Contents

- `cases.jsonl`: 480 case variants, one JSON object per line.
- `manifest.json`: counts, generator/schema versions, seed, split sizes, and
  SHA-256 checksums.

Regenerate from the repository root with:

```bash
cd forensic-framework
.venv/bin/python generate_warrant_benchmark.py
```

The virtual-environment path is illustrative; any compatible Python 3.11+
environment with `requirements.txt` installed may be used.

## Composition

- 48 independent base cases.
- 12 families, with four base cases per family.
- 24 attack and 24 benign base cases.
- 10 paired variants per base case.
- 12 development and 36 test base cases.
- 480 total case-condition records.

All variants of one base case remain in one split. The base case, rather than a
variant or model sample, is the independent statistical unit.

## Families

Attack families:

- credential compromise;
- session hijacking;
- staged data exfiltration;
- privilege abuse;
- destructive administration; and
- exposed API credentials.

Benign or attempted-attack families:

- authorized maintenance;
- international travel;
- scheduled backup;
- quarter-end reporting;
- authorized security testing; and
- failed credential stuffing without successful access.

## Paired variants

Each base case has the following variants:

1. canonical;
2. alerts withheld;
3. misleading alert actor;
4. misleading alert severity;
5. strong unsuccessful decoy;
6. counterevidence removed;
7. decisive evidence removed;
8. irrelevant noise;
9. provider-style schema drift; and
10. passive prompt injection in an explicitly untrusted log field.

The `canonical` and context-only variants preserve core event evidence. Evidence
removal variants record every removed identifier. Noise, decoy, and adversarial
events are tagged in ground truth.

## Two different labels

Every record separates:

- `latent_incident_label`: whether the scenario generator enacted an attack;
  and
- `warranted_verdict`: whether the visible evidence warrants `YES`, `NO`, or
  `INSUFFICIENT`.

This distinction is intentional. Removing decisive evidence does not change
what happened in the hidden scenario, but it changes what a responsible
investigator may conclude from the remaining evidence. Similarly, removing
benign counterevidence produces `INSUFFICIENT`, not an artificial attack.

## Record schema

Each JSONL record contains:

- case, base-case, family, split, and variant identifiers;
- user baselines;
- normalized or intentionally drifted visible events;
- detector alerts, treated as untrusted hypotheses;
- hidden incident and suspect labels;
- the verdict and suspect warranted by visible evidence;
- decisive, counterevidence, removed, irrelevant, and adversarial event IDs;
- reference findings and the subset whose required evidence remains visible;
- mutation log; and
- sampled generation parameters.

## Intended uses

- Evaluate citation validity separately from semantic claim warrant.
- Measure verdict and actor flips under controlled context changes.
- Evaluate counterevidence recall and evidence-starvation abstention.
- Compare events-only and events-plus-alerts investigation.
- Test schema and prompt-injection robustness.
- Evaluate calibration and selective risk with base-case-clustered statistics.

## Out-of-scope uses

- Claims about production prevalence or real analyst workload.
- Training or evaluating autonomous punitive, disciplinary, or blocking tools.
- Treating synthetic account identifiers as human attribution evidence.
- Counting 480 variants as 480 independent incidents.
- Tuning prompts or thresholds on the test partition.

## Known limitations

- Families are generated from authored templates and do not capture the full
  diversity, ambiguity, or collection defects of production cloud evidence.
- Event metadata includes explicit authorization fields in some cases to make
  warrant labels auditable; real systems often lack this clarity.
- Four base cases per family limit precise family-specific effect estimates.
- Passive prompt injection represents one adversarial-log mechanism, not the
  full LogInject threat space.
- Synthetic personas, paths, IP ranges, and timestamps are not evidence of
  external validity.
- Reference findings are generator-derived and require independent expert
  review before they can serve as the sole forensic reference standard.

## Privacy and safety

The benchmark contains no real users, organizations, credentials, or routable
attack infrastructure. IP addresses use documentation ranges where external
addresses are needed. Embedded prompt-injection text is inert data and is
marked `untrusted_content=true`.

## Licensing

No standalone dataset license has yet been assigned. Until the repository owner
selects one, use and redistribution follow the repository's stated terms. A
specific open-data license must be selected before a public archival release.

