---
name: owasp-top10-review
description: Security review of a web app or API the user is building, against OWASP Top 10:2025 and OWASP API Security Top 10:2023 (plus OWASP LLM Top 10 when the app calls an LLM). Reviews source code, config, dependencies, CI and Docker files. Can also run passive checks on a local or staging app. Writes a prioritized report with file:line evidence, the OWASP/CWE mapping, and concrete fixes.
when_to_use: Use whenever the user wants to check, audit or review the security of their own app, API or repo. This includes "is this secure", pre-launch or pre-deploy checks, "find vulnerabilities", OWASP compliance, security review of a PR or diff, and "ตรวจความปลอดภัย / เช็คช่องโหว่ / ตรวจ OWASP". Also use when they mention IDOR/BOLA, SQL injection, XSS, SSRF, CSRF, JWT/auth or session problems, leaked secrets, vulnerable dependencies, security headers or CORS for their codebase, even if they never say "OWASP". Do not use it for questions about OWASP in general with no codebase to check, or for attacking systems the user doesn't own.
license: CC-BY-SA-4.0 AND MIT
argument-hint: "[path | diff [base-branch]] [--url http://localhost:PORT] [--quick]"
allowed-tools:
  - Bash(bash ${CLAUDE_SKILL_DIR}/scripts/detect_stack.sh *)
  - Bash(python3 ${CLAUDE_SKILL_DIR}/scripts/summarize_findings.py *)
---

# OWASP Top 10 review

Find real, exploitable risks in the user's own web app or API. Tie each one to code, map it to OWASP Top 10:2025 and
API Security Top 10:2023, and give a fix the developer can apply today. The value is in **verified findings with
evidence and fixes**. A checklist of generic advice or a pile of unverified scanner output does not help.

Arguments: `$ARGUMENTS`. If there are none, review the current project root in full mode.

## Ground rules
Why these rules matter: the user will trust this report, and running it must never harm anyone.

- **Own code and own environments only.** Runtime checks go to `localhost` or a staging URL the user says they own.
  Never touch production or third-party hosts, never do anything destructive, and never brute-force. Verification
  probes stay benign. For example, "user A requests user B's order and expects 403" is fine; exploit payloads are not.
- **Scanners give leads, not findings.** Confirm each hit by reading the code path. False positives erode trust faster
  than misses do. Record dismissed leads with a one-line reason.
- **Redact secrets everywhere** in the report and in chat. Show the first 4 characters plus `****`, the file:line and
  the secret type. Never paste a full key.
- **Don't install tools or change code without asking.** Report first, then offer to fix. Missing scanners are listed
  with install hints. Reviewing the code by hand still covers most of what the scanners would have found.
- **Write defensively: no attack payloads.** Describe a vulnerable input by its class and effect, for example "a
  `template` value containing shell metacharacters is interpreted by `/bin/sh`". Do not write a working string such as
  a shell chain, SQLi string or script tag. Verify fixes with tests that assert the safe behaviour: `execFile` is called
  with an argv array, the query uses placeholders, user B gets a 404 for user A's order. Why: the report is pasted into
  tickets and PRs, a payload adds nothing to the fix, and exploit-style text can make safety filters abort the run
  before the report is written. Never build or run a PoC exploit.
- **Never claim "secure" or "compliant".** Say "no issues found in the reviewed scope". The Top 10 is an awareness
  document. For compliance, point to ASVS 5.0 (Level 1 minimum, Level 2 recommended for most apps).
- **Language:** write the report and chat summary in the user's language. Keep category names, CWE IDs, code and
  file paths in English.

## Workflow

Output folder: `<project>/.security-review/<YYYY-MM-DD>/` (call it `$OUT`). If `.gitignore` doesn't cover
`.security-review/`, tell the user and suggest adding it. Don't edit `.gitignore` yourself.

### 1. Scope
- **Mode.** Full repo is the default. A **path** argument (e.g. `src/api`) limits the review to that folder. Still
  read the shared code it depends on, such as auth middleware, config and data access, and say in the report which
  parts were out of scope. `diff [base]` reviews the files changed vs `base` (default `main`/`master`):
  `git diff --name-only <base>...HEAD` plus uncommitted changes. In diff mode, still check that new or changed routes
  pass through the auth and authorization middleware, and that changed queries and outbound calls are safe. Cross-file
  context is where diff reviews miss bugs.
  Keep issues that already existed before the diff out of the verdict. List at most 3 of them briefly under
  "Pre-existing (not in this PR)" and rate them on their own merits rather than inflating them.
- **`--quick`** skips scanners and does only a manual review of the highest-risk categories: A01, A07, A05, A02 and API1–API5.
- **Web vs API.** Apply the API Security Top 10 whenever the app exposes JSON, GraphQL or gRPC endpoints, which covers
  most modern apps. Apply the LLM Top 10 section when an LLM SDK is present.

### 2. Recon
Run `bash ${CLAUDE_SKILL_DIR}/scripts/detect_stack.sh . $OUT/inventory.md`.

Then build the **attack-surface map** yourself and save it to `$OUT/attack-surface.md`. Every later step depends on it:
- Entry points: routes, controllers, resolvers, server actions, webhooks, jobs and queue consumers. Note which are
  public and which require authentication.
- Authentication: session vs JWT vs OAuth, where tokens are issued and verified, password reset, MFA.
- Authorization model: roles, tenant boundaries, ownership checks, and where these are enforced (middleware, guards,
  policies, or inside each handler).
- Data layer: ORM/raw queries, NoSQL filters, file storage.
- Outbound calls: HTTP clients, webhooks, third-party APIs, LLM calls (these are candidates for SSRF, API10 and API4).
- Rendering: templates, `dangerouslySetInnerHTML`/`v-html`/`|safe`.
- Config and deploy: env files, debug flags, CORS, headers, cookies, Dockerfiles, CI workflows, IaC.

For a big codebase, sample representatively and say which parts were not reviewed.

### 3. Automated scans (skip with `--quick`)
Tell the user in one line what will run and what goes over the network. Semgrep downloads its rules. OSV and the
npm/pnpm/yarn audit tools send package names and versions to advisory APIs. No source code is uploaded.

```bash
bash ${CLAUDE_SKILL_DIR}/scripts/run_scanners.sh . --out $OUT          # add --offline to skip networked tools
python3 ${CLAUDE_SKILL_DIR}/scripts/summarize_findings.py $OUT     # -> $OUT/scanner-findings.md (leads by category)
```
Triage `scanner-findings.md` during step 4: confirm each lead or dismiss it. For dependency CVEs, check whether the
vulnerable package or function is actually reachable. If so, keep the advisory's severity. If it is a dev-only or
unreachable dependency, lower it and say why.
If a scanner fails, for example because the network blocks rule downloads, record that in the report's limitations
and move on. Don't write custom rules or hunt for workarounds: the manual review covers the same ground, and
workarounds cost more time than they save.

### 4. Manual review, category by category
How much reference material to load depends on the size of the repo. The detailed reference files total about 100k
tokens, and a small app doesn't need them to be reviewed well.
- **Small repos (under about 5k LOC of source):** read all the source files directly and use
  `references/quick-checklist.md`, which covers every category on one page. Open a category's detailed reference
  (`references/web/Axx-*.md` or `references/api/APIx-*.md`) only when you have a finding there and need the
  framework-specific fix, the ASVS ID or a severity anchor, or when you are unsure how to judge something.
- **Larger repos:** for each category, use the **"How to detect — code review"** section of its detailed reference,
  for the detected stacks only. Run its `rg` patterns, then read the surrounding code.

Go roughly in risk order: **A01 → A07 → A05 → A02 → A04 → A03 → A08 → A10 → A06 → A09**. Handle the API categories
together with the web category they map to: API1/API3/API5/API7 with A01, API2 with A07, API8/API9 with A02,
API10 with A08/A05, and API4/API6 with A06.

Scanners are nearly blind to the following. Spend real effort here, because these are where the serious bugs usually hide:
- **Authorization (A01, API1, API3, API5):**
  - For every handler that takes an object ID, trace whether the query is scoped to the caller: owner, tenant, or
    role. `findById(req.params.id)` without such scoping is the classic bug.
  - Check that admin routes carry role checks on the server.
  - Check that response serializers do not leak internal fields.
  - Check that create and update handlers don't bind the whole `req.body` (mass assignment).
- **Business logic (A06, API6, API4):**
  - Prices, quantities and discounts must come from the server.
  - Multi-step flows must be enforced on the server.
  - Look for race conditions on balances and coupons.
  - Check for caps on pagination and payload size, and for rate limits on costly or sensitive flows.
- **Exceptional conditions (A10):**
  - `catch` blocks that allow access or return success.
  - Swallowed errors.
  - Stack traces or exception text sent to clients.
  - Partial writes without a transaction.
- **Logging and alerting (A09):**
  - Are auth and authz failures logged?
  - Do secrets or PII end up in logs?
  - Is anything alerting on these events?
- **Inventory and third-party use (API9, API10):**
  - Old `/v1` routes or debug endpoints still mounted.
  - Third-party responses trusted without validation, timeouts or redirect limits.

**Large repos:** if you can spawn subagents and the repo is bigger than about 20k LOC, or the user asks for a deep
review, split step 4 into 5 parallel reviewers:
1. A01 + API1/3/5/7
2. A07 + A04 + API2
3. A05 + A10 + API10
4. A02 + A03 + A08 + API8/9
5. A06 + A09 + API4/6

Give each reviewer the paths to `attack-surface.md`, `scanner-findings.md`, its reference files and the finding format
below. Have each write to `$OUT/findings/<group>.md`. Then merge the results yourself, de-duplicate them, and apply
the filing rules.

### 5. Runtime checks (optional, only with `--url` or if the user offers a running app)
- `bash ${CLAUDE_SKILL_DIR}/scripts/check_headers.sh <url> --out $OUT/runtime-headers.md` runs passive checks: headers,
  cookies, a 404 error page, and CORS with a foreign Origin. The script refuses non-local hosts unless `--allow-remote`
  is passed. Use that flag only for a staging host the user has confirmed they own.
- **Two-user authorization test:** do this only if the user provides test tokens for two accounts. Request one user's
  resource with the other user's token and expect 403 or 404. It is the single most valuable runtime check.
- A ZAP baseline scan (passive, Docker) is available on request; see `references/tooling.md` §1.6. Never run active
  scans (ZAP full/API scan, nuclei fuzzing) unless the user explicitly opts in and the target is disposable.

### 6. Rate each finding
**Severity = Likelihood × Impact** (OWASP Risk Rating). Note which factors you applied, so the rating can be reproduced.

| Likelihood \ Impact | Low | Medium | High |
|---|---|---|---|
| **High** | Medium | High | Critical |
| **Medium** | Low | Medium | High |
| **Low** | Info | Low | Medium |

- **Likelihood**
  - High: reachable unauthenticated or by any logged-in user, trivial to trigger, or a live secret.
  - Medium: needs a specific role, state or chaining.
  - Low: needs an admin or an unusual config.
- **Impact**
  - High: RCE, auth bypass, other users' or tenants' data, bulk PII or credentials, payment abuse, a prod-scope secret.
  - Medium: limited data exposure, stored XSS in a low-privilege area, DoS of one feature.
  - Low: version leaks, missing hardening headers.
- **Anchors**
  - Critical: SQLi on a public route; a live cloud key in git history; IDOR on `/api/orders/:id`; no authorization on `/admin/*`.
  - Medium: missing CSP/HSTS; a session cookie without HttpOnly or Secure; no rate limit on login.
  - Low: `X-Powered-By` present.
- **Dependency CVEs** keep the advisory's CVSS band (label it `CVSS-B`) and are adjusted for reachability.
- **Confidence** is recorded separately: Confirmed / Likely / Needs manual verification.

File every finding under **one primary category**, using the filing rules in `references/category-map.md`. For
example, SSRF goes under A01, mass assignment under A08, hard-coded credentials under A07, and exception text returned
to clients under A10 while debug mode goes under A02. Add the API ID and CWE as tags. Group repeats of the same pattern
into one finding ("and 6 similar at …").

### 7. Report
Follow `${CLAUDE_SKILL_DIR}/assets/report-template.md` and write it to `$OUT/report.md`, **in stages**:
1. Write the header, the coverage matrix and an empty findings section.
2. Append the findings in batches of a few at a time.
3. Fill in the executive summary last.

A long single write that gets interrupted loses everything, while a staged report keeps what is already written.

The reader is a busy developer, so keep it tight. A small app should produce roughly 150–350 lines.
- **Critical and High** get a full block with these parts:
  - a plain-words title and the category tags (2025 + API 2023 + CWE)
  - `file:line` and confidence
  - at most 8 lines of evidence, redacted
  - the concrete impact in this app
  - a code fix written for this codebase, not a generic one
  - a one-line verification
- **Medium, Low and Info** get one table row each: severity, title, tags, `file:line`, and a one-line fix.
- **Repeats** of the same pattern are grouped into one finding.

The coverage matrix must list all 10 categories, plus the 10 API categories when they apply, each with a status. That
way the reader sees what was checked, not only what was found.

The chat reply should be about 12 lines or fewer, in the user's language:
- the overall risk and a go/no-go (or merge/don't-merge) verdict
- counts by severity
- the top 3 actions
- the report path

Then offer to fix the findings, starting with Critical and High, and to add the scanners to CI and pre-commit.

## References (read on demand)
- `references/quick-checklist.md`: a one-page "what to look for" list covering every web and API category. Start here.
- `references/category-map.md`: category tables, the 2021→2025 changes, filing rules, the full CWE→category lists, and the LLM Top 10 note.
- `references/web/A01…A10-*.md`: for each category, the issue, root causes, key CWEs, code-review patterns per stack (Node, Python, Java, Go, PHP, .NET), runtime checks, tools, fixes with code, a checklist (ASVS 5.0 IDs) and severity guidance.
- `references/api/API1…API10-*.md`: the same content for the API Security Top 10:2023, with GraphQL and gRPC notes.
- `references/tooling.md`: scanner commands and flags as of 2026-09, the security-header and cookie baseline, ASVS 5.0 levels, and the severity rubric.
  Includes a supply-chain warning: Trivy releases v0.69.4–0.69.6 were compromised in March 2026, so pin scanner versions.
