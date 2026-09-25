# Evals

> ⚠️ The apps in `fixtures/` are **intentionally vulnerable**. They exist only for testing this skill.
> Do not deploy them or run them on a network. The keys in them are AWS's public documentation examples, not real credentials.

The dependency manifests are renamed (`*.fixture.*`) so that GitHub dependency alerts ignore them.
`setup-fixtures.sh` restores the real names and builds each fixture's git history.

```bash
bash evals/setup-fixtures.sh ./eval-work
```

This creates three fixtures:

| Fixture | Prompt (see `evals.json`) | Tests |
|---|---|---|
| `shop-api` | Thai: full review before a production deploy | Express: JWT decoded without verify + fail-open, SQLi, IDOR, mass assignment, BFLA, SSRF, legacy unauthenticated export, client-side price, committed secrets, vulnerable deps, DOM XSS |
| `notes-api` | English: API security pass before beta | FastAPI: JWT signature not verified, BOLA, SQLi, pickle/yaml deserialization, command injection, SSRF + TLS off, unsigned webhook, BFLA, swallowed exceptions, traceback leak, password logging |
| `billing-svc` | Thai: review branch `feature/invoice-pdf` vs `main` | Diff scope, route mounted before auth middleware, missing tenant scoping, command injection, SSRF; no false positives on the unchanged, secure code |

To run the evals:
1. Open Claude Code in each fixture folder and send the prompt from `evals.json`.
2. Check the report in `.security-review/<date>/report.md` against the `expectations` list.
3. For A/B benchmarking, repeat the run without the plugin enabled. The
   [skill-creator](https://github.com/anthropics/skills) workflow can grade the runs and aggregate the results.
