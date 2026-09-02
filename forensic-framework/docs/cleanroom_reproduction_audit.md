# Clean-room Reproduction Audit

Date: 2026-09-02

## Scope

This audit tested the anonymous, raw-transcript-omitted artifact as a reviewer
would receive it. The archive was extracted into a new temporary directory, a
new Python virtual environment was created from the packaged lock file, and the
exact command printed in `ARTIFACT_README.md` was run without access to the
repository working tree.

## Result

- the synthetic benchmark integrity check passed;
- all 101 tests shipped in the artifact passed;
- 5,400 synthetic and 360 external records were reanalyzed;
- both base-case-clustered, 10,000-resample statistical analyses completed;
- release-record SHA-256 values matched their redaction reports;
- the omitted-raw policy reported 4,236 synthetic and 197 external response
  files as deliberately absent, with zero retained raw files and no integrity
  errors;
- tables and vector figures regenerated;
- Tectonic and BibTeX compiled a 12-page US-Letter PDF; and
- extracted text from the regenerated PDF was identical to the frozen paper.

The PDF byte hash is not expected to match across Tectonic builds because PDF
container metadata may change. The reported text, record hashes, tables,
figures, and statistical inputs are the reproducibility targets.

## Release-policy boundary

`--allow-omitted-raw` accepts only complete transcript omission. It rejects a
partially present raw-response set and still checks the SHA-256 value of every
retained response. The default mode remains strict and rejects any missing raw
response. Pairing invariants and release-record hashes are checked in both
modes.

This audit establishes computational reproducibility of the released proxy
analysis. It does not replace the independent expert annotation, adjudication,
institutional determination, or author approval required before submission.
