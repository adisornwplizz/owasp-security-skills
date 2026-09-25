**Verdict: don't open the beta yet. Overall risk is Critical.** Both of the things you were worried about are real problems. `current_user` decodes JWTs with `verify_signature: False`, so anyone can mint a token for any user, including an admin. And `GET /notes/{id}` never checks who owns the note, so any user can read every note just by stepping through the IDs.

Findings: **8 Critical · 6 High · 5 Medium · 3 Low · 2 Info.** I ran bandit and read all 152 lines by hand. Semgrep couldn't download its rules, and nothing was tested against a running app.

Fix first:
1. **Auth** (`app/security.py`, `app/settings.py`): verify HS256 signatures, require `exp`, and move the signing key to an env var. The current key is committed to git, so treat it as leaked and replace it (F-001, F-002, F-013).
2. **Remove the remote-code-execution and SSRF paths:** pickle/`yaml.Loader` in `/notes/import`, `shell=True` with the `filename` parameter in export-pdf, and the open `/avatar` fetch (F-006, F-007, F-009).
3. **Access control:** check the owner in `get_note` and export, parameterize `/notes/search` (it has SQL injection), add a real admin check on `/admin/stats`, and verify billing-webhook signatures (F-003, F-004, F-005, F-008).

Also before launch: passwords are stored as unsalted SHA-1, and every login writes the password to the log in plain text (F-010, F-011).

The full report with file:line evidence and fixes is at `.security-review/2026-09-25/report.md`. Add `.security-review/` to a `.gitignore`; the repo doesn't have one yet. Want me to start fixing the Criticals and Highs, with a two-user authorization test, and add bandit, semgrep, pip-audit and gitleaks to CI and pre-commit?
