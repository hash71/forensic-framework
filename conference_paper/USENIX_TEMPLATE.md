# USENIX template provenance

`usenix.sty` was obtained from the official USENIX Security 2027 LaTeX
template archive and rechecked on 2026-09-03:

<https://www.usenix.org/sites/default/files/usenixsecurity2027_latex_templates.zip>

The upstream file has SHA-256
`2278c83173e084a00fcf76d3227acb971f5137ecea993a5b4e13a9b2bd67b45e`.
The vendored file is functionally byte-identical; only one terminal newline may
be present locally. `conference_paper/build_pdf.py` verifies this digest before
every build.

The 2027 call requires the official style and forbids changes to formatting
defaults. For that reason, the previous Tectonic/XeTeX compatibility edit has
been removed. The manuscript is compiled with pdfLaTeX and BibTeX, matching the
style's engine assumptions. Tectonic is not a supported submission build because
the official style's `microtype` spacing option is pdfTeX-only.

The container pins its base-image digest and Debian package snapshot. The build
also fails before promoting its output if the PDF is not U.S. Letter, contains
author/title metadata, exceeds 20 total pages, has an unembedded font, or
disagrees with the final LaTeX log's page count.

Before submission, the PDF must also pass the conference's open-source format
checker and the vendored style must be rechecked if USENIX updates its archive.
