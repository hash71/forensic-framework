# Expert Annotation: Recruitment, Consent, and Data Handling

Protocol date: 2026-09-02
Status: required pre-recruitment checklist; no expert labels may be collected
until every institutional and compensation field below is resolved

## Purpose and roles

The study asks two independent digital-forensics and incident-response (DFIR)
experts to label the evidential warrant and materiality of synthetic forensic
claims. A third qualified expert adjudicates disagreements after the two
independent files are frozen. Annotators are research contributors to the
reference standard, not model operators, benchmark authors, or hidden sources
of incident data.

## Minimum qualification

Each reviewer must satisfy at least one of the following and must be able to
interpret authentication, file, cloud audit, and administrative event records:

- two or more years of professional DFIR, security-operations, threat-hunting,
  or cloud incident-response experience;
- a current, relevant professional certification plus practical incident
  investigation experience; or
- peer-reviewed research or graduate-level teaching in digital forensics or
  incident response.

The release records only aggregate, non-identifying qualifications: reviewer
role, experience band, qualification category, and whether the reviewer was
independent of benchmark design. Names, employers, email addresses, exact
certification numbers, and free-form biographies are not placed in the
anonymous artifact.

## Required determination before recruitment

The authors must record the responsible institution's determination about
human-participant review before recruiting or collecting labels. This document
does not presume that the activity is exempt or outside review. Record the
determination identifier, date, responsible office or committee, and approved
consent procedure in a private study log; report the determination accurately
in the final paper without exposing reviewer identity.

## Consent and withdrawal

Before opening the annotation package, each reviewer receives a plain-language
description of the research purpose, tasks, estimated time, compensation,
synthetic nature of the evidence, inert prompt-injection strings, data retained,
publication plan, and contact for questions. Participation is voluntary.
Reviewers may stop at any time and may withdraw their labels until the stated
de-identification and analysis cutoff. Consent is recorded separately from the
anonymous label file.

## Compensation and workload

Compensation, currency, payment method, estimated hours, and any pilot-based
per-item timing must be fixed before recruitment and reported to reviewers.
Compensation must reflect skilled professional work and may not depend on
agreement with the benchmark, another reviewer, or the mechanical evaluator.
The offline interface records active-visible seconds per item so the final
manuscript can report aggregate workload and median annotation time. It stores
no wall-clock timestamps and sends no telemetry. Reviewers are told about this
measurement before consent. Compensation covers the agreed workload rather
than depending on the timer. Compensation terms are intentionally not guessed
in advance.

## Independence and blinding

- Reviewers do not see model identity, system condition, family, mutation,
  expected verdict, latent incident label, or the mechanical label.
- The two primary reviewers work independently and do not exchange labels or
  rationales before their CSV hashes are frozen.
- The adjudicator sees the two labels and rationales but not reviewer identity
  or system metadata.
- Reviewer IDs are opaque codes and are hashed in the analysis output.

## Data minimization and security

The items contain synthetic or licensed synthetic records, not production
employee data. Annotation is performed offline. No analytics, remote fonts,
network calls, cookies, or third-party scripts are present in the interface.
Consent records and payment information are stored separately from labels.
Only de-identified labels, aggregate qualifications, aggregate timing, and
adjudicated rationales are candidates for release.

## Preflight record

The private study log must contain all of the following before labels begin:

- institutional determination and approved consent text;
- qualification evidence checked for all three reviewers;
- conflict-of-interest and benchmark-independence declaration;
- compensation terms and estimated workload;
- annotation pilot showing that instructions are understandable;
- exact annotation-package and instruction-file SHA-256 hashes;
- planned de-identification cutoff and withdrawal deadline; and
- contact responsible for adverse events, questions, and data deletion.

Missing fields block expert annotation and submission. Model-generated labels
cannot replace this process.

The repository provides an explicitly unapproved
`expert_annotation_consent_template.md` and a public
`expert_annotation_preflight.md` to make these dependencies concrete. The
responsible institution must approve the actual procedure; repository text
cannot grant that approval.
