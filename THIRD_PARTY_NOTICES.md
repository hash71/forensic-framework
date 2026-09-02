# Third-Party Notices

This file identifies third-party material carried by this repository and its
anonymous research artifact. It is not a license for the repository as a
whole. Except where a component-specific license is stated below, no
repository-wide public license has yet been granted.

## CERT Insider Threat Test Dataset r4.2

The external transfer study contains adapted material from:

- **Title:** *Insider Threat Test Dataset*, release 4.2
- **Creator:** Brian Lindauer
- **Publisher:** Carnegie Mellon University, Software Engineering Institute
- **DOI:** <https://doi.org/10.1184/R1/12841247.v1>
- **Source record:** <https://kilthub.cmu.edu/articles/dataset/12841247>
- **License:** Creative Commons Attribution 4.0 International
  (<https://creativecommons.org/licenses/by/4.0/>)

The affected release material includes
`forensic-framework/data/warrant_external/` and the external-run records under
`forensic-framework/data/warrant_runs/external-cert-r4_2-remote-fusion-gemma-v1_4-r3/`.
Aggregated external results in the paper and generated tables are also derived
from those records.

**Modifications made for this study:** forty synthetic user-month windows were
selected using the documented seeded case-control procedure; fields were
selected and normalized; generated email and web text, long list fields, and
non-evidentiary derived fields were removed; URLs were reduced to hosts; 39
windows were downsampled to 150 events; records were converted to compact
JSONL; and model/evaluator outputs and aggregate statistics were computed from
the adapted records. The source's latent insider answer key was retained only
as an operational evaluation target, not as claim-level forensic ground truth.

The CC BY 4.0 license applies to the upstream material and adapted portions,
not automatically to independently authored code, the original WarrantLab
benchmark, model-generated text, or the paper as a whole. No endorsement by
Brian Lindauer, Carnegie Mellon University, or the Software Engineering
Institute is implied. The upstream material is provided under the license's
disclaimer of warranties and limitation of liability.

## Gemma 4

The experiments used local and remotely served Gemma-family deployments.
Google's official Gemma 4 model card identifies the model family as
Apache-2.0 licensed: <https://ai.google.dev/gemma/docs/core/model_card_4>.

No Gemma model weights or model source code are distributed here. The included
Ollama `Modelfile` records a local wrapper configuration, and the artifact
contains scored structured output content and derived analyses. Raw provider
transcript files are omitted from the anonymous artifact. Public archival
or anonymous-review release of retained remote-endpoint output content remains
conditional on the authors confirming the applicable endpoint-operator
agreement; the Gemma 4 model license alone does not establish the separate
operator's terms.

## Publication templates

`conference_paper/usenix.sty` is the unmodified functional content of the
official USENIX Security 2027 conference style file distributed from
<https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip>.
The upstream file's SHA-256 is recorded in `conference_paper/USENIX_TEMPLATE.md`
and enforced by the paper build. It is included so reviewers can rebuild the
required USENIX-formatted paper with pdfLaTeX.

Historical IEEE paper directories contain `IEEEtran.cls` and `IEEEtran.bst`.
Their own headers identify the files as LPPL 1.3 works, retain the upstream
copyright and contributor notices, and require modified files to be marked.
They are not included in the anonymous WarrantLab artifact.

## Installed dependencies

Python, PHP, JavaScript, TeX, and system dependencies are installed separately
and are not vendored in the anonymous artifact. Their package-specific licenses
continue to apply. The dependency lock files identify versions for
reproduction but do not relicense those packages.
