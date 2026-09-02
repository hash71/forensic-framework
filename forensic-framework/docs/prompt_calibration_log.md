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
