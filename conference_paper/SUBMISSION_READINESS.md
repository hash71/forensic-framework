# Submission Readiness: USENIX Security 2027

Primary target: [USENIX Security 2027, Cycle 2](https://www.usenix.org/conference/usenixsecurity27/call-for-papers)

This target fits the paper's security-systems contribution: forensics and
diagnostics, intrusion and anomaly analysis, and cloud security. The submission
should be categorized by the security task, not as a generic machine-learning
paper. The paper is already typeset with the official USENIX style on U.S.
letter paper.

Digital Forensics Conference Europe 2027 is a strong domain-specific
alternative, but its 10-page full-paper deadline is September 25, 2026 (title
and abstract September 18). It is viable only if the institutional and expert
annotation gates finish in time; the deadline does not justify submitting the
current proxy-only draft.

## Fixed dates (Anywhere on Earth)

- Mandatory registration: January 19, 2027
- Paper submission: January 26, 2027
- Artifact grace-period deadline: January 29, 2027

The title, full author list, and topics are fixed at registration; the abstract
must be non-blank but remains tentative. Every author needs a HotCRP profile and
ORCID before submission.

## Venue requirements

- At most 13 pages of body text; references and submission appendices are
  excluded from that limit. An accepted camera-ready paper has a 20-page total
  limit including references and appendices.
- Anonymous author block and anonymous, non-tracking artifact URL.
- A mandatory Open Science appendix describing every artifact or explaining
  why it cannot be shared.
- A clearly labeled ethics discussion is strongly encouraged and is present in
  the manuscript.
- The paper must be complete at submission; reviewers are not required to read
  optional appendices.
- ML-assisted security work should use the primary field of the security
  problem, remain relevant to systems security, and state the attacker, threat
  surfaces, trust assumptions, generality, and practicality. The manuscript now
  gives an explicit analyst-assistance threat model and keeps autonomous action
  outside scope.
- Human authors must verify all AI-assisted prose, code, data, references, and
  results. Fabricated citations or results are academic misconduct.

For the anonymous artifact, USENIX recommends `anonymous.4open.science` with
conference identifier `SEC27`. The URL becomes final after paper submission;
the three-day grace period may be used only to anonymize and upload artifacts,
not to change the paper, and the frozen files must remain accessible through
the shepherd-approval deadline.

## Evidence gates before submission

- [x] Corrected synthetic run is complete, checksum-verified, and frozen.
- [x] External CERT r4.2 transfer run is complete and frozen.
- [ ] Two independent DFIR experts label the frozen claim sample.
- [ ] Disagreements are adjudicated by a third qualified reviewer.
- [ ] The responsible institution's human-participant determination, consent
  procedure, qualification screening, and compensation terms are documented
  before recruitment.
- [ ] Inter-rater agreement and human-versus-mechanical error analysis are in
  the paper.
- [x] All current tables, figures, confidence intervals, and prose regenerate
  from the frozen artifacts with one command.
- [x] The frozen confidence gate has a checksum-bound post-hoc audit; it fits no
  calibrator, selects no held-out threshold, and keeps H5 explicitly untested.
- [x] A three-role, 400-claim AI-judge sensitivity panel is reported as
  exploratory judge-dependence evidence, never as human or expert validation.
- [x] A separate 120-claim post-hoc priority package is ready for expert
  diagnosis and is explicitly excluded from population-prevalence inference.
- [x] No claim describes CERT's latent answer key as visible-evidence warrant
  ground truth.
- [x] The invalidated role-leaking pilot is excluded from every estimate and
  disclosed as a protocol deviation.
- [x] The reviewer artifact is identity-scrubbed and passes the automated
  environment without secrets or workstation paths.
- [x] The raw-transcript-omitted archive reproduces both analyses, figures,
  and the 14-page manuscript (11 body pages followed by appendices and
  references) from a fresh virtual environment using its documented command.
- [x] Raw endpoint transcript files are omitted from the reviewer archive.
- [x] A top-level third-party notice preserves CERT r4.2 attribution, its CC BY
  4.0 link, the affected paths, and the study's modification statement.
- [ ] Endpoint-operator terms confirm redistribution of the structured output
  content retained in scored records; raw-file omission alone does not prove
  this permission. Do not upload the current reviewer ZIP until this is
  confirmed or an aggregate-only replacement is built.
- [x] The artifact builder defaults to a visibly non-distributable local build
  and rejects anonymous-review/public targets until all license and endpoint
  attestations are dated and checksum-bound.
- [x] An aggregate-only fallback excludes every structured record, per-item AI
  judgment, and claim-bearing annotation package, passes a long-output-overlap
  scan, and states that frozen statistics cannot be recomputed from it.
- [x] The current results PDF is within the body-page limit, prints intelligibly in
  grayscale, embeds its fonts, and contains no author identity.
- [ ] Authors approve the final paper, author order, title, ORCIDs, ethics
  statement, and artifact-release license before registration.

The code can complete all but the human-label and author-approval gates. Those
two gates must remain explicit; neither model-generated labels nor silent
assumptions can substitute for them.
