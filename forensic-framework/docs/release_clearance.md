# Release-clearance gate

The artifact builder has two content profiles and three distribution targets.
`structured-output` supports result-level reproduction and retains parsed model
content. `aggregate-only` excludes per-record outputs, per-item judgments, and
annotation packages that reproduce generated claims; its weaker
reproducibility boundary is stated in the archive README.

- `local-validation`: permits unresolved approvals, but labels the ZIP **do not
  upload or share**;
- `anonymous-review`: fails unless every required release gate is approved;
- `public-release`: applies the same fail-closed checks and records the stronger
  public-release target in the manifest.

Unless `--output` is supplied, the filename includes both profile and target
(for example, `warrantlab-aggregate-only-local-validation.zip`) so a local
archive is not easily mistaken for a reviewer release.

The authoritative declaration is
`config/release_clearance.json`. It contains no endpoint URL, token, author
identity, or private agreement. Each approved gate must record an exact
decision, a UTC approval time, and the SHA-256 of the underlying approval or
terms evidence. Keep identity-bearing evidence in the institution's controlled
records; the anonymous artifact carries only its digest.

## Required human decisions

1. `code_license`: the copyright holder selects an exact code license.
2. `original_benchmark_license`: the copyright holder selects exact terms for
   the original WarrantLab benchmark and labels.
3. `paper_release_terms`: all authors confirm that the paper/PDF distribution
   is consistent with the venue agreement.
4. `endpoint_output_redistribution`: the account holder or other authorized
   party identifies the public Modal deployment and confirms that the
   applicable agreement permits redistribution of its retained structured
   output.

The last gate applies to the `structured-output` profile and cannot be closed
merely by citing Gemma's Apache-2.0 model
license. The endpoint used by the frozen experiment is a public `modal.run`
deployment, and this repository contains neither its deployment source nor an
account-ownership record. Modal's current Software as a Service Agreement,
effective May 2026, defines Input and Output as Customer Data and says that the
Customer owns Customer Data as between Modal and that Customer. The repository
does not establish that a paper author is that Customer, nor whether another
operator imposed terms on callers. See <https://modal.com/legal/terms>.

For each approved gate, replace `pending` with `approved` and fill all three
fields:

```json
{
  "status": "approved",
  "decision": "exact license or permission decision",
  "evidence_sha256": "64 lowercase hexadecimal characters",
  "approved_utc": "2026-09-03T12:00:00Z"
}
```

Then request the intended target explicitly:

```bash
.venv/bin/python build_anonymous_artifact.py \
  ... \
  --distribution-target anonymous-review
```

If the endpoint permission cannot be established, use the reduced profile:

```bash
.venv/bin/python build_anonymous_artifact.py \
  ... \
  --omit-raw \
  --content-profile aggregate-only \
  --distribution-target anonymous-review
```

For `aggregate-only`, the endpoint-output gate is recorded as not applicable.
The code, original-benchmark, and paper-release gates still must be approved.
The build also rejects record, raw-response, annotation, and per-judgment paths
and scans retained release text for 16-word overlap with source model output.

The builder checks completeness, syntax, the frozen endpoint digest, and the
current `THIRD_PARTY_NOTICES.md` digest before creating a distribution-cleared
archive. These checks make unresolved decisions visible and fail closed; they
do not replace legal or institutional review of the underlying evidence.
