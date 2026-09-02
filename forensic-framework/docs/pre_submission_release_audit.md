# Pre-Submission Release Audit

Audit date: 2026-09-03

## Result

The current computational release is internally reproducible and suitable for
independent review, but it is intentionally **not submission-ready**. The
remaining scientific gate is adjudicated DFIR-expert annotation under the
responsible institution's approved or exempted procedure. Author approval,
artifact licensing, and anonymous hosting also remain open.

This audit covers the proxy-results manuscript and must be repeated after any
human-label integration or substantive manuscript change.

## Evidence checked

### Code and reproduction

- `python -m pytest -q`: 175 tests passed.
- `php artisan test --compact`: 2 Laravel tests passed.
- The one-command paper reproduction validated the 48-base-case,
  480-case-variant benchmark, reanalyzed 5,400 synthetic and 360 external
  records, reran both 10,000-resample statistical analyses, regenerated all
  tables and figures, and compiled the manuscript.
- Both generated figure PDFs are byte-reproducible; their builders use
  invariant metadata and a regression test compares independent outputs.
- The anonymous archive is separately rebuilt and tested from a fresh virtual
  environment before every release commit.

### Statistical claims

- Synthetic inference clusters all variants and repetitions within the 36
  held-out `base_case_id` units; repetitions are not counted as independent
  samples.
- The primary comparison is paired on base case and reports a base-case
  cluster bootstrap confidence interval. The failed 3-point attack-recall
  non-inferiority test remains visible in the abstract, results, and conclusion.
- The abstention mechanism is a fixed heuristic at one operating point, not a
  calibrated confidence policy. The paper now enumerates its 0.65 generator-
  confidence threshold and every rule-based rejection trigger; verifier
  confidence is recorded but unused. H5 remains not confirmatorily testable.
- The 32-cluster CERT transfer analysis is explicitly separate and uses latent
  scenario labels only for operational stress testing, not as visible-evidence
  warrant ground truth.
- The 400-claim, three-role AI panel is labeled judge-sensitivity evidence and
  is barred from the human-analysis path. Its low chance-adjusted agreement and
  reviewer-dependent endpoint are reported rather than averaged away.
- The 120-claim AI-prioritized package is post-hoc diagnostic material. It
  cannot estimate population prevalence and cannot replace the frozen
  probability sample.

### References and novelty

- Every one of the 35 manuscript citation keys has a matching BibTeX entry and
  a primary-source locator in `conference_paper/REFERENCE_AUDIT.md`.
- All audited publisher, proceedings, JMLR/PMLR, and arXiv links resolved on
  the audit date; every listed DOI resolved or reached its publisher.
- The audit corrected the IEEE DOI for *LLM-Powered Automated Cloud Forensics*
  and the BibTeX accent in Michael Färber's name.
- The September 2026 refresh added GAVEL and now distinguishes its atomic
  evidence-contract debate for open-book fact checking from WarrantLab's
  forensic semantic axes, paired evidence/context mutations, and downstream
  risk--coverage estimand.

### Format and anonymity

- The PDF is U.S. Letter, two-column, 13 pages total, and the main body ends on
  page 11, below the 13-page body limit.
- Ethical Considerations and Open Science are explicit appendices A and B,
  placed after the main body and before the references.
- All fonts are embedded. The build log has no overfull boxes, undefined
  citations, undefined references, or fatal errors; changed pages were rendered
  and visually inspected.
- PDF metadata contains no author identity. The anonymous artifact excludes
  Git history and raw endpoint transcripts, records all payload hashes, and
  must pass its absolute-path, credential-pattern, and identity scans.

### Ethics boundary

- The benchmark is synthetic and contains no real users, routable
  infrastructure, credentials, or executed attack payloads.
- Passive prompt-injection strings are inert test data. The system is scoped to
  analyst assistance and is not permitted to autonomously accuse, block, or
  discipline a person.
- No expert labels have been collected. Repository templates do not constitute
  institutional approval, consent, qualification screening, or compensation.

## Gates that still block submission

1. Obtain and record the responsible institution's human-participant
   determination before recruitment.
2. Have two qualified DFIR experts independently label the frozen probability
   sample and a third qualified reviewer adjudicate disagreements.
3. Generate the checksum-bound human analysis, rerun the paper pipeline, and
   repeat this audit against the changed results and prose.
4. Have every human author verify all AI-assisted text, code, data, references,
   and results; approve title, author order, ORCIDs, ethics language, and the
   artifact/dataset license.
5. Freeze the artifact at an anonymous, non-tracking URL that remains available
   for the full review period, then insert that URL into appendix B.
