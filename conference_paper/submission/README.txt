TERM PAPER SUBMISSION — Md. Nazmul Hasan
Title: Augmenting Rule-Based Private-Cloud Forensic Investigation with
       Evidence-Grounded LLM Reasoning

CONTENTS (per submission guideline)
  A. Term paper (PDF) ......... Hasan_TermPaper.pdf   (12 pp., IEEE double column)
  B. Source files ............. source/
       paper.tex             — LaTeX source
       references.bib        — BibTeX bibliography (47 cited, all verified)
       IEEEtran.cls/.bst     — IEEE template (so it compiles as-is)
       figures/              — result figures (PDF) used by the paper
       diagrams/             — system diagrams (PDF) used by the paper
  C. Presentation slides ...... Hasan_Presentation.pptx   (15 slides, 10-min talk)

PAPER STRUCTURE (maps to the recommended structure A–G)
  A. Abstract
  B. Introduction  → includes the "Our Contribution" subsection (bullets)
                     and Table I comparing this work with related approaches
  C. Background
  D. Related Work (Survey)  → Table II compares the surveyed work threads
  E. Future Directions
  F. Conclusion
  G. References

TO COMPILE
  latexmk -pdf paper.tex      (or: pdflatex → bibtex → pdflatex ×2)
  Requires the figures/ and diagrams/ subfolders alongside paper.tex.

NOTE ON FIGURES
  Figures are committed as PDF (vector). They are generated programmatically
  from the evaluation artifacts; the generation scripts live in the project
  repository (regenerate_figures.py for result figures, make_diagrams.py for
  system diagrams) and reproduce every figure from data/statistics_report.json.
