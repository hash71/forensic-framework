# Release Licensing Audit and Author Decision Record

Audit date: 2026-09-03

## Current result

The public repository and anonymous artifact do not yet have an
author-approved repository-wide license. The external CERT-derived material is
redistributable under its upstream CC BY 4.0 license when attribution and
modification notices are preserved; `THIRD_PARTY_NOTICES.md` now records those
terms and the affected release paths. This closes the missing-notice defect but
does **not** close the author license-approval gate.

The hosting service currently detects no repository license. Under GitHub's
official licensing guidance, a public repository without a license remains
under default copyright rules except for the limited viewing and forking rights
in GitHub's service terms. The previous sentence "Not licensed for commercial
use" was not a complete or standard license grant and has been replaced with
an explicit pending status.

This is an engineering release audit, not legal advice.

## Primary-source evidence

- The KiltHub/Figshare API record for DOI
  `10.1184/R1/12841247.v1` identifies *Insider Threat Test Dataset*, creator
  Brian Lindauer, and license CC BY 4.0:
  <https://api.figshare.com/v2/articles/12841247>.
- CC BY 4.0 permits sharing adapted material and requires creator attribution,
  a license notice/link, and an indication of modifications:
  <https://creativecommons.org/licenses/by/4.0/legalcode>.
- Google's Gemma 4 model card identifies the model family as Apache-2.0:
  <https://ai.google.dev/gemma/docs/core/model_card_4>.
  Google's general Gemma terms page explicitly redirects Gemma 4 to that
  separate license, so output language in the general terms is not treated as
  permission for this deployment: <https://ai.google.dev/gemma/terms>.
- GitHub explains the effect of publishing a repository without a license:
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/licensing-a-repository>.
- USENIX Security 2027 requires an Open Science appendix, anonymous
  non-tracking review access, and public availability of shareable artifacts
  on acceptance:
  <https://www.usenix.org/conference/usenixsecurity27/call-for-papers>.

## Component decision matrix

| Component | Present status | Required decision or evidence |
| --- | --- | --- |
| Independently authored source code | No public license selected | Repository owner approves an exact SPDX license and copyright line. Apache-2.0 is recommended for its explicit patent grant; BSD-3-Clause is a simpler permissive alternative. |
| Original WarrantLab synthetic benchmark and labels | No standalone data license selected | Authors approve an exact data license. CC BY 4.0 is recommended for broad research reuse with attribution; CC BY-SA 4.0 is the reciprocal alternative. |
| Paper text and figures | No repository release license selected | Authors reconcile the chosen preprint/artifact terms with the venue publication agreement. |
| Adapted CERT r4.2 records and derived portions | Upstream CC BY 4.0 confirmed | Preserve `THIRD_PARTY_NOTICES.md`, the DOI, creator, license link, modification statement, and no-endorsement boundary. Do not present a project-wide license as replacing this notice. |
| Gemma-family model weights | Not distributed | No weight redistribution decision is required for the current artifact. Preserve model provenance and the official Apache-2.0 model-card link. |
| Retained structured output from the configured remote endpoint | Public `modal.run` deployment confirmed; account holder unverified | Modal's May 2026 agreement treats Input and Output as Customer Data and says the Customer owns Customer Data as between Modal and that Customer. The repository does not prove that an author is the deployment's Customer or that no separate caller terms apply. Authors must archive account-holder/operator evidence before sharing retained content. Omitting raw transcripts alone is insufficient because parsed model content remains in scored records. |
| `usenix.sty` | Functionally byte-identical official USENIX Security 2027 style; upstream SHA-256 enforced before compilation | Preserve the source link and digest. Confirm any additional public-archive requirement with USENIX before the permanent post-acceptance release. |
| Historical `IEEEtran` files | LPPL 1.3 notices retained in file headers | Keep their headers and modification rules; they are outside the anonymous artifact. |
| Package dependencies | Not vendored | Preserve version locks; package-specific licenses apply when installed. |

## Author approval block

The following must be filled by a human copyright holder before a public
archival release. A checked box must name the exact license; it cannot merely
say "open" or "research use."

- [ ] Code license approved: `____________________________`
- [ ] Original benchmark/data license approved: `____________________________`
- [ ] Paper/preprint release terms approved: `____________________________`
- [ ] Remote endpoint output-redistribution terms archived at:
  `____________________________`
- [ ] `THIRD_PARTY_NOTICES.md` reviewed against the final payload manifest.
- [ ] Final anonymous and post-acceptance archive terms reviewed by all authors.

Until the endpoint entry is complete, the current structured-output artifact
must not be uploaded even for confidential conference review; use an
aggregate-only build if permission cannot be established. Until the remaining
entries are complete, it must not be described as an openly licensed public
release.

Artifact schema v1.6 implements that aggregate-only fallback. It excludes all
structured records, raw outputs, per-item AI judgments, and annotation packages
that reproduce generated claims, then scans retained release text against
16-word fingerprints of the source outputs. This removes the endpoint-output
gate for that reduced profile while truthfully giving up recomputation of the
frozen statistics. Code, original-benchmark, and paper approvals still apply.

The machine-readable `config/release_clearance.json` now enforces this boundary.
Its safe default is `local-validation`, which emits a visibly non-distributable
archive. `anonymous-review` and `public-release` targets fail closed until each
human decision includes an exact decision, approval time, and evidence digest.
The control prevents accidental upload but does not substitute for review of
the underlying agreements. Modal terms checked 2026-09-03:
<https://modal.com/legal/terms>.
