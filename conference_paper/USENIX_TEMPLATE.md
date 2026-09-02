# USENIX template provenance

`usenix.sty` was obtained from the official USENIX Security 2026 LaTeX
template archive on 2026-09-02:

<https://www.usenix.org/sites/default/files/usenixsecurity2026_latex_templates.zip>

The 2027 call links the USENIX Security template and retains the same required
letter-paper, two-column, 10-point Times, 12-point-leading, 7-by-9-inch text
block. The vendored style has two engine-compatibility conditionals:

1. `breakurl` is loaded only under pdfTeX because it emits PostScript hooks that
   fail under Tectonic's XeTeX engine; the manuscript loads `xurl` instead.
2. microtype's pdfTeX-only kerning/spacing features are disabled under XeTeX.

The official pdfTeX path and all layout dimensions are unchanged. Before
submission, the PDF must also pass the conference's format checker and the
repository must be rechecked against the latest official 2027 template.
