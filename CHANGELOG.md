# Changelog

## 1.0.2 — 2026-09-25

- Corrected the Top 10:2025 release date. Per the OWASP/Top10 repository history, the release-candidate label was removed on 2025-12-24, not in January 2026.
- Pointed the reference link to the new official site, top10.owasp.org.
- Re-verified on 2026-09-25 that 2025 is still the current edition. Articles titled "OWASP Top 10 2026" either relabel the 2025 list or reprint the 2017 list.

## 1.0.1 — 2026-09-25

- README: full usage guide (quick start, install options, how a run works, reading the report, next steps, update/uninstall, troubleshooting) in English and Thai.
- Skill: a path argument (e.g. `src/api`) now explicitly scopes the review to that folder, as `argument-hint` already advertised.

## 1.0.0 — 2026-09-25

First public release.

### Skill: `owasp-top10-review`
- Reviews against OWASP Top 10:2025 and API Security Top 10:2023, with an OWASP LLM Top 10 section when an LLM SDK is detected.
- Workflow steps:
  1. Scope: full repo, `diff [base]` or `--quick`.
  2. Recon and attack-surface map.
  3. Optional scanners.
  4. Manual review, category by category.
  5. Optional passive runtime checks.
  6. Rating (likelihood × impact).
  7. Staged report.
- References:
  - a quick checklist
  - a category map with filing rules and the full CWE→2025 lists
  - 10 web and 10 API deep-dive files
  - scanner and tooling notes
- Scripts:
  - `detect_stack.sh`: inventory of the project.
  - `run_scanners.sh`: runs installed scanners only and redacts secrets.
  - `summarize_findings.py`: converts SARIF/JSON results into 2025 categories.
  - `check_headers.sh`: passive checks, local hosts only by default.
- Evals: three intentionally vulnerable fixtures (Express, FastAPI, PR diff). The skill passed 35/36 assertions; the baseline passed 24/36.

### Docs
- Sample reports in `examples/` (English FastAPI and Thai Express).
