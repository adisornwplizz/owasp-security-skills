# Attribution

The files under `plugins/owasp-security/skills/owasp-top10-review/` (`SKILL.md`, `references/`, `assets/`) are
adapted works. They summarize, restructure and extend material from the OWASP projects listed below, with
additional research drawn from framework documentation and tool documentation. This repository licenses them under
[CC BY-SA 4.0](LICENSE).

| Source | Copyright | License |
|---|---|---|
| [OWASP Top 10:2025](https://owasp.org/Top10/2025/) ([source](https://github.com/OWASP/Top10)) | © 2003–2025 The OWASP Foundation, Inc. | CC BY-SA 4.0 |
| [OWASP API Security Top 10:2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) ([source](https://github.com/OWASP/API-Security)) | © OWASP Foundation | CC BY-SA 4.0 |
| [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) ([source](https://github.com/OWASP/CheatSheetSeries)) | © OWASP Foundation | CC BY-SA 4.0 |
| [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS) | © OWASP Foundation | CC BY-SA 4.0 |
| [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llm-top-10/) | © OWASP Foundation | CC BY-SA 4.0 |
| [OWASP Risk Rating Methodology](https://owasp.org/www-community/OWASP_Risk_Rating_Methodology) | © OWASP Foundation | CC BY-SA 4.0 |

CWE identifiers and names come from [MITRE CWE](https://cwe.mitre.org/) (© The MITRE Corporation).

**Changes made:**
- The categories were condensed into review checklists.
- Code-review detection patterns were added for each stack, along with runtime checks, remediation snippets, filing
  rules and a severity rubric.
- The content was reorganized for use by an AI coding agent.

Category contents were verified against the official sources as of 2026-09-25. Some places in the references note
where the official pages contain errors, for example the A03:2025 page lists CWE-447 where CWE-477 is meant.

This project is not affiliated with or endorsed by the OWASP Foundation. OWASP® is a registered trademark of the OWASP Foundation, Inc.

The scripts in `scripts/` and `evals/setup-fixtures.sh` are original work under the [MIT License](LICENSE-MIT).
