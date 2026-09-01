# Forensic Claim-Warrant Annotation Guide

Version: 1.0  
Applies to: evidential-warrant benchmark v2

## 1. Annotation question

For each atomic claim, answer:

> Do the cited events, considered together and without importing unstated
> assumptions, justify the exact wording and strength of this claim?

The task is not to decide whether the claim might be true in the hidden world.
It is to decide what the visible evidence warrants.

## 2. Overall labels

### SUPPORTED

The cited evidence establishes every material component of the claim at the
stated strength. Minor wording differences that do not change meaning are
acceptable.

Example:

- Claim: `user_07 downloaded /data/hr/payroll.csv at 03:12`.
- Evidence: a successful `file_download` event naming `user_07`, that exact
  resource, and that timestamp.
- Label: `SUPPORTED`.

### CONTRADICTED

The cited evidence directly conflicts with at least one material component.

Example:

- Claim: `user_07 successfully logged in`.
- Evidence: the cited event records `login_failed` with `status=failure`.
- Label: `CONTRADICTED`.

### INSUFFICIENT

The evidence is relevant or compatible but does not establish the full claim.
This includes overstatement, omitted alternatives, unjustified causal or intent
language, and attribution to an actor whose account merely appears in the log.

Example:

- Claim: `user_07 intentionally stole payroll data`.
- Evidence: a successful file download by the account, with no evidence of the
  human operator's identity, authorization, or intent.
- Label: `INSUFFICIENT`.

### NOT_APPLICABLE

Use only when the claim field does not express the axis being annotated. It is
not a substitute for uncertainty.

## 3. Atomicity

A claim should contain one independently checkable proposition. Split a claim
when different parts could receive different labels.

Not atomic:

> `user_04 logged in from a Tor exit node, escalated privileges, and exfiltrated
> 2 GB to an external host.`

Atomic form:

1. `user_04's account successfully authenticated from IP X.`
2. `IP X is categorized as a Tor exit node in the supplied evidence.`
3. `user_04's account changed its role from read_only to admin.`
4. `2 GB left the monitored environment for external host Y.`
5. `The transfer was caused by the authenticated user_04 session.`

The fifth claim requires linkage evidence beyond the first four.

## 4. Claim types

### Observation

A direct restatement of one or more event fields. Observation claims may use
`OBSERVED` modality only when the cited fields match.

### Derived fact

A deterministic transformation of events, such as a count, duration, ordering,
or comparison with a supplied baseline. The derivation must be reproducible.

### Hypothesis

An explanation compatible with evidence but not uniquely established, such as
credential compromise, malicious intent, or session hijacking. Hypotheses must
use calibrated language and acknowledge material alternatives.

### Decision

A verdict, attribution, escalation, or abstention. A decision is supported only
when its stated threshold is met by supported underlying claims.

## 5. Semantic axes

Annotate every applicable axis independently before assigning the overall
label.

### Actor

Does the evidence establish the claimed account, process, host, or human actor?
An account identifier establishes account activity, not necessarily the human
who controlled it. A claim naming a person requires identity evidence.

### Action or predicate

Distinguish attempts from successes and observations from interpretations:

- `login_failed` does not support successful access;
- `file_read` does not support exfiltration;
- `role_change` does not by itself support privilege abuse; and
- `log_delete` does not by itself support intent to conceal.

### Object or resource

The file, database, host, role, or service must match. A directory-level claim
may be supported by multiple child-resource events only if scope is explicit.

### Time and chronology

Check exact timestamps, intervals, ordering, time zones, and words such as
`before`, `after`, `immediately`, and `within`. Do not infer chronology from the
order in which records are displayed.

### Quantity

Recompute counts, byte totals, rates, durations, and thresholds from the cited
events. Approximate language must still be within the tolerance defined in the
case metadata.

### Scope

Terms such as `all`, `multiple`, `organization-wide`, `only`, or `every` require
evidence covering the stated population. A sample cannot support a universal
claim.

### Modality

Evaluate whether the linguistic force matches the evidence:

- `observed` or `confirmed` requires direct support;
- `probable` requires stronger support than material alternatives;
- `possible` requires compatibility and some positive evidence; and
- `unknown` or `insufficient` is appropriate when decisive evidence is absent.

### Authorization

Successful access is not necessarily authorized; unusual access is not
necessarily unauthorized. Authorization claims require policy, role, ticket,
approval, ownership, or equivalent evidence supplied in the case.

### Intent

Intent is rarely observable in machine logs. Words such as `maliciously`,
`deliberately`, `to steal`, or `to hide` normally require corroborating evidence
or must be framed as hypotheses.

### Causality

Temporal proximity and shared identifiers do not automatically establish that
one event caused another. Check session, process, network-flow, request, or
other explicit linkage.

### Decision strength

A `YES` decision requires evidence meeting the case's incident definition. A
`NO` decision means the evidence affirmatively supports a benign resolution;
it is not interchangeable with missing data. Use `INSUFFICIENT` when neither an
incident nor a benign explanation is warranted.

## 6. Counterevidence

Counterevidence is evidence that weakens a material part of the leading
hypothesis. Examples include:

- a valid maintenance ticket matching time, actor, and scope;
- successful MFA tied to the expected device;
- a failed login with no later success;
- a file path inside the user's authorized role;
- privileges reverted within the approved window;
- transfer destination owned by the organization; or
- evidence assigning the decisive action to another actor.

Merely listing counterevidence is not enough. The final claim must reflect its
weight. A high-confidence attack verdict that ignores decisive exculpatory
evidence remains insufficient or contradicted.

## 7. Decisive claims

Mark a claim `decisive=true` if removing or weakening it would reasonably change
one of the following:

- incident verdict;
- primary suspect;
- attack-chain stage;
- severity or escalation; or
- decision to abstain.

Supporting detail and stylistic narrative are non-decisive unless they alter
one of these outputs.

## 8. Handling citations

- First check whether every cited ID exists.
- Then inspect only the cited events for primary warrant.
- Additional uncited evidence in the case does not repair an incorrect
  citation, but it may be recorded as a citation-completeness error.
- A valid event ID attached to an unsupported claim is not grounded evidence.
- One citation at the end of a paragraph does not automatically support every
  proposition in that paragraph.

## 9. Common error patterns

1. **Account-to-human leap:** treating an account event as proof of a person's
   intent or physical action.
2. **Attempt-to-success leap:** calling failed authentication a breach.
3. **Read-to-exfiltration leap:** calling local access external transfer.
4. **Temporal-to-causal leap:** interpreting sequence as causation.
5. **Alert parroting:** restating alert actor, severity, or technique without
   independent event support.
6. **Citation laundering:** citing a related real event for stronger wording
   than the event warrants.
7. **Counterevidence omission:** reporting only evidence favoring the selected
   hypothesis.
8. **Benign-is-absence error:** returning `NO` when the correct disposition is
   `INSUFFICIENT`.
9. **Quantity inflation:** reporting totals not reproducible from cited events.
10. **Montage error:** combining individually true observations into a false
    overall narrative.

## 10. Annotation workflow

1. Read the claim without model identity or condition metadata.
2. Verify citation identifiers.
3. Inspect the cited events.
4. Label each applicable semantic axis.
5. Identify counterevidence and missing evidence.
6. Assign overall warrant using the most serious material axis failure.
7. Mark materiality and decisiveness.
8. Write a one- or two-sentence rationale.
9. Record uncertainty; do not resolve ambiguity by guessing.

## 11. Adjudication

The adjudicator sees both independent labels and rationales but not model
identity. The adjudicator records a final label and reason, preserving the
original annotations. Guideline changes discovered during development are
versioned. After final test annotation begins, clarifications may explain an
existing rule but may not change label definitions without reporting a protocol
deviation and re-annotating affected claims.

