# Final submission package

Everything in this directory is final except `paper.pdf`. Two minutes to produce it:

1. Go to <https://www.overleaf.com>, sign in (free account works), New Project → Upload Project.
2. Zip just `paper.tex` and `IEEEtran.cls` from this directory and upload.
3. Hit Recompile. The PDF should build with no warnings or `??` cross-references.
4. Download the PDF, save as `paper.pdf` in this directory.
5. Run `zip -r submission.zip paper.pdf paper.tex IEEEtran.cls Project_Presentation.pptx` from this directory.

## Files

- `paper.tex` — IEEE conference source, single column. Author block: Md. Nazmul Hasan; institution / city / email still placeholder.
- `IEEEtran.cls` — IEEE class file.
- `Project_Presentation.pptx` — 10-slide deck rebuilt from scratch to match the final paper (title, problem ×2, method, four primary scenarios, headline, S14, S15, limitations, conclusion).
- `paper.pdf` — produced by step 1–4 above.

## Notes

- The pipeline figure is inline TikZ; no separate `.pptx` or `.png` is needed.
- The deck uses the source theme/master from `Project_Presentation.pptx` so colours/fonts match what you had before.
- If you want to add author email / institution / city later, edit lines 28–34 of `paper.tex` and recompile.
