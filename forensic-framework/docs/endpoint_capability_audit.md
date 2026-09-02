# Remote Endpoint Capability Audit

Observed: 2026-09-02T03:18:54Z
Endpoint SHA-256: `b70491802b316a1f01c0d461a3a335fb8e886052d7a998d2afc9cad4c785bb37`

A read-only query to `/version` and `/v1/models` on the same endpoint used for
the frozen experiment returned:

- requested and returned alias: `fusion-gemma`;
- served-root label: `gemma-4-26B-A4B-it` (the `/models/` server prefix is
  omitted from released metadata);
- advertised maximum context: 32,768 tokens;
- serving implementation: vLLM 0.19.0; and
- no system fingerprint, immutable weight digest, source repository revision,
  or provider-side model revision.

The endpoint URL and authorization material are not recorded. The model-list
`created` field changed between consecutive queries and was therefore treated
as response-generation time, not a model-build timestamp. The served-root
label improves model-family disclosure but is not an immutable identifier. All
results remain claims about the endpoint hash and frozen run artifacts, not
about every checkpoint in the Gemma family.

## Upstream-name and output-release audit

Google's official Gemma documentation lists `gemma-4-26b-a4b-it` as a Gemma 4
model identifier and its model card identifies the family as Apache-2.0
licensed. The capitalization-insensitive name matches the served-root label,
which supports the family attribution but still does not authenticate the
weights, quantization, fine-tuning, or revision actually served. The official
Gemma terms also state that Google claims no rights in generated outputs.

Those upstream statements do not establish the terms imposed by the operator
of this separately configured endpoint. Until the endpoint operator's service
terms are archived and reviewed, a public artifact may release prompts,
structured scored records, response hashes, and aggregate results, but raw
model transcripts remain conditional. This is a release-policy precaution,
not a claim that the transcripts are prohibited.

Primary upstream records (checked 2026-09-02):

- <https://ai.google.dev/gemma/docs/core/model_card_4>
- <https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api>
- <https://ai.google.dev/gemma/terms>
