# Evidence-Grounded Cloud Forensics Research Project

This monorepo contains the implementation, evaluation artifacts, service layer,
paper, and supporting project documentation for the private-cloud forensic
investigation study.

## Repository layout

| Path | Purpose |
| --- | --- |
| `forensic-framework/` | Python forensic pipeline, rules, LLM integration, validators, experiments, tests, and dashboard |
| `forensic-laravel/` | Laravel API/orchestration and audit layer |
| `conference_paper/` | Current IEEE paper source, figures, appendix, presentation, and final submission artifacts |
| `paper_drafts/` | Earlier paper and presentation source material |
| Root documents | Proposal, literature-review material, experiment notes, screenshots, and project history |

The original `forensic-framework` Git history is preserved within this
repository. New work should be committed from the monorepo root.

## Tracking policy

Source code, experiment specifications, processed scenarios, model outputs,
statistics, paper sources, figures, and final submission artifacts are tracked
so that reported results can be audited. Secrets, local environments,
dependencies, caches, runtime databases, temporary render output, and
third-party sample papers are intentionally excluded by `.gitignore`.

Never commit `.env` files or credentials. Use the checked-in `.env.example`
files as configuration templates.

## Main development commands

Run the Python tests from `forensic-framework/`:

```bash
uv run --with-requirements requirements.txt --with pytest pytest -q
```

Run the Laravel tests from `forensic-laravel/` after installing Composer
dependencies:

```bash
php artisan test --compact
```

Build the paper from `conference_paper/` with a LaTeX installation that
supports `latexmk` and the included IEEE class and bibliography style.
