# Evidence-Grounded Cloud Forensics Research Project

This monorepo contains the implementation, evaluation artifacts, service layer,
paper, and supporting project documentation for the private-cloud forensic
investigation study.

## Repository layout

| Path | Purpose |
| --- | --- |
| `forensic-framework/` | Python forensic pipeline, rules, LLM integration, validators, experiments, tests, and dashboard |
| `forensic-laravel/` | Laravel API/orchestration and audit layer |
| `conference_paper/` | Current USENIX-format paper source, generated tables/figures, appendices, and submission-readiness audits |
| `paper_drafts/` | Earlier paper and presentation source material |
| Root documents | Proposal, literature-review material, experiment notes, screenshots, and project history |

The original `forensic-framework` Git history is preserved within this
repository. New work should be committed from the monorepo root.

## Tracking policy

Source code, experiment specifications, processed scenarios, run manifests,
release checksums, aggregate statistics, paper sources, and reproducible figures
are tracked so reported results can be audited. Large confirmatory JSONL files,
per-call transcripts, final PDFs, and release ZIPs are carried in deterministic
checksum-bound research artifacts rather than ordinary Git history. Secrets,
local environments, dependencies, caches, runtime databases, temporary render
output, and third-party sample papers are intentionally excluded by
`.gitignore`.

Never commit `.env` files or credentials. Use the checked-in `.env.example`
files as configuration templates.

## Main development commands

Run the Python tests from `forensic-framework/`:

```bash
python -m pip install -r requirements-research.lock
python generate_warrant_benchmark.py --check-only
python -m pytest -q
```

Run the Laravel tests from `forensic-laravel/` after installing Composer
dependencies:

```bash
php artisan test --compact
```

Regenerate verified analysis artifacts from `forensic-framework/` with
`reproduce_warrant_paper.py`, then build the manuscript from
`conference_paper/` with pdfLaTeX and the unmodified official USENIX 2027
style:

```bash
python3 build_pdf.py
```

The paper directory also contains a Dockerfile with an immutable base-image
digest and Debian package snapshot for hosts without a local TeX Live
installation.

GitHub Actions repeats the frozen-benchmark check, research test suite, Python
compile check, and isolated official-template PDF build for every change under
`forensic-framework/` or `conference_paper/`.

## Licensing status

No repository-wide public license has been selected yet. Default copyright
rules therefore apply except where a file or third-party component states its
own license. Before a public archival research release, the copyright holders
must approve separate terms for the independently authored code, original
benchmark data, and paper materials. See
[`forensic-framework/docs/release_license_audit.md`](forensic-framework/docs/release_license_audit.md)
for the decision record and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
for component-specific attribution and license boundaries.

The artifact release gate and its safe local-only default are documented in
[`forensic-framework/docs/release_clearance.md`](forensic-framework/docs/release_clearance.md).
The builder also provides a verified aggregate-only profile when redistribution
of the frozen endpoint's structured output cannot be established.
