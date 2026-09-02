# Warrant Study Model Inventory

Updated: 2026-09-02

This inventory distinguishes reproducible model artifacts from aliases whose
serving revision is unknown. A successful smoke test establishes only that the
model can participate in the structured protocol; it is not a performance
result.

| Study label | Provider | Model / immutable revision | Size | Development status |
|---|---|---|---:|---|
| `remote-fusion-gemma` | configured OpenAI-compatible endpoint | alias `fusion-gemma`; runtime-reported root label `gemma-4-26B-A4B-it`; endpoint hash `b70491802b316a1f01c0d461a3a335fb8e886052d7a998d2afc9cad4c785bb37`; revision and weight digest not exposed | server label: 26B-A4B | 12-family canonical development run complete; calibration only |
| `local-craid-e4b` | Ollama | `craid-e4b-local:latest`; `sha256:88121c70e887f9e7b2e882bf3dea3d91e276574e308587bac70f55727b0fb856` | 7.5B, Q4_K_M | strict one-case smoke retained; malformed output counted as failure |
| `local-gemma4-e4b` | Ollama | wrapper `forensic-warrant-gemma4-e4b:v1`; `sha256:3d609a2c293731e30619621ada2b4f05697225082bf03a67eb0982cf23b1323b` | 7.5B, Q4_K_M | strict one-case smoke valid; 16,384-token context wrapper is versioned |
| `local-qwen3-0.6b` | Ollama | `qwen3:0.6b`; `sha256:7df6b6e09427a769808717c0a93cadc4ae99ed4eb8bf5ca557c90846becea435` | 751.63M, Q4_K_M | strict one-case smoke valid; conservatively abstained |

## Reproducibility notes

- The Gemma wrapper changes only the configured context window. Its versioned
  Modelfile is `config/ollama/Modelfile.gemma4-e4b-warrant`.
- Local manifests record both the model digest and the raw response hash.
- The remote capability audit records vLLM 0.19.0, a 32,768-token advertised
  context, and the served-root label, but these do not substitute for an
  immutable weight digest. The deployment cannot support a cross-provider or
  model-family-wide claim.
- The served-root name matches Google's documented `gemma-4-26b-a4b-it`
  identifier, but raw-transcript release remains conditional until the
  separately configured endpoint operator's service terms are archived. The
  upstream model card and output terms alone do not answer that operator-level
  question.
- No credentials for two independent frontier API providers are available in
  the experiment environment. The protocol target of two frontier providers is
  therefore currently unmet and must be described as a limitation unless
  access is supplied before confirmatory inference.
- Available disk space was approximately 5 GB before adding Qwen; the compact
  0.6B model was selected to avoid displacing pre-existing user models or
  risking the workspace with a multi-gigabyte download.
