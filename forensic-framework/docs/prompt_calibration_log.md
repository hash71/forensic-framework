# Prompt Calibration Log

This log records every prompt change informed by model output. Calibration uses
only cases assigned to the development split. No test case may be inspected to
change a prompt, parser, validator, abstention threshold, or condition.

## 2026-09-02 — generator v1.0 to v1.1

- **Cases inspected:** `fw2_001__canonical` only (development split).
- **Model label:** `fusion-gemma` through the configured OpenAI-compatible
  endpoint. The endpoint did not return an immutable model revision or system
  fingerprint, so this run is calibration evidence only.
- **Outcome:** the verdict and suspect matched the reference and all citations
  resolved, but the unwarranted decisive-claim rate was 1.0. The mechanical
  abstention policy correctly rejected the output.
- **Observed contract failures:** paraphrased action names (`successful_login`,
  `log_deletion`), source IPs placed in the resource object field, invented
  service scopes, and causal-parent links without an explicit linkage key.
- **Change:** generator v1.1 requires exact normalized event actions and
  resources for observations, restricts scope and time, limits causal parents
  to explicit linkage identifiers, and restates the authorization and modality
  rules.
- **Unchanged:** benchmark records, reference labels, evaluator logic,
  abstention thresholds, statistical plan, and held-out test split.

## 2026-09-02 — generator v1.1 to v1.2

- **Cases inspected:** `fw2_001__canonical` only (development split).
- **Model:** local `craid-e4b-local:latest`, immutable Ollama digest
  `sha256:88121c70e887f9e7b2e882bf3dea3d91e276574e308587bac70f55727b0fb856`.
- **Outcome:** the model returned syntactically complete JSON but used the
  cited event ID `evt_fw2_001_004` as a causal parent for two claims. The strict
  schema rejected the output because causal parents must reference claim IDs.
- **Change:** generator v1.2 explicitly says that
  `causal_parent_claim_ids` accepts only claim IDs already in the output and
  never event IDs. No parser repair or post-hoc coercion was added.
- **Unchanged:** benchmark, labels, evaluator, abstention thresholds,
  statistics, and held-out split.

## 2026-09-02 — generator v1.2 to v1.3

- **Cases inspected:** `fw2_001__canonical` only (development split), on the
  hosted alias and local Craid model.
- **Outcome:** both models produced schema-valid outputs. The hosted model
  treated failed attempts as a causal parent of a later login despite no shared
  allowed linkage key. Craid added free-form semantic `derived_fact` claims
  (`successful unauthorized access`, `harmful change`) that were not expressed
  as deterministic counts, durations, orderings, or baseline comparisons.
- **Change:** generator v1.3 restricts this experiment to direct observations,
  non-decisive hypotheses, and a decision; disallows inferred causal links from
  account/IP/time alone; and constrains the decision subject to the reported
  suspect account or null.
- **Rationale:** this narrows the generated representation to propositions the
  frozen deterministic validator can check. Richer interpretations remain in
  alternative hypotheses for human annotation and the alert-blind verifier.
- **Next step:** v1.3 is the candidate frozen generator prompt for aggregate
  calibration across all 12 canonical development families. No further prompt
  change may use held-out output.

## 2026-09-02 — generator v1.3 to v1.4 (final development revision)

- **Cases inspected:** `fw2_001__canonical` only (development split), in a
  hosted generator-verifier smoke test.
- **Outcome:** the generator marked its `YES` decision decisive but marked all
  direct observations used by that decision non-decisive. The independent
  verifier found the observations supported, while the deterministic decision
  check correctly reported that no non-decision decisive claim backed the
  verdict.
- **Change:** generator v1.4 requires every observation necessary to the
  decision to be marked decisive and referenced by the decision claim.
- **Freeze:** v1.4 is the final prompt revision. The aggregate 12-family
  development run is diagnostic only; no further prompt or evaluator change
  will be made from model-quality results. Held-out output remains unseen.
