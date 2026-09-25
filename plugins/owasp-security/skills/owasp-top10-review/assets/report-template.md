# OWASP Security Review — {{project name}}

> Standard: OWASP Top 10:2025{{ + OWASP API Security Top 10:2023}}{{ + OWASP LLM Top 10 (2026)}}
> Date: {{YYYY-MM-DD}} · Scope: {{full repo | diff vs <base> | path}} · Commit: {{sha}} ({{branch}}{{, uncommitted changes}})
> Reviewer: Claude (owasp-top10-review skill) — automated + manual code review{{ + passive runtime checks on <url>}}

## 1. Executive summary

**Overall risk: {{Critical | High | Medium | Low}}** — {{one sentence why}}

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| {{n}} | {{n}} | {{n}} | {{n}} | {{n}} |

**Fix first:**
1. {{F-00x — one line, the action, not the vulnerability}}
2. {{…}}
3. {{…}}

## 2. Coverage matrix

Status legend: ❌ issues found · ⚠️ needs manual verification / partially reviewed · ✅ no issues found in reviewed scope · N/A not applicable

| Category | Status | Findings | Notes |
|---|---|---|---|
| A01:2025 Broken Access Control | | | |
| A02:2025 Security Misconfiguration | | | |
| A03:2025 Software Supply Chain Failures | | | |
| A04:2025 Cryptographic Failures | | | |
| A05:2025 Injection | | | |
| A06:2025 Insecure Design | | | |
| A07:2025 Authentication Failures | | | |
| A08:2025 Software or Data Integrity Failures | | | |
| A09:2025 Security Logging & Alerting Failures | | | |
| A10:2025 Mishandling of Exceptional Conditions | | | |
{{if API:}}
| API1:2023 BOLA | | | |
| API2:2023 Broken Authentication | | | |
| API3:2023 BOPLA | | | |
| API4:2023 Unrestricted Resource Consumption | | | |
| API5:2023 BFLA | | | |
| API6:2023 Sensitive Business Flows | | | |
| API7:2023 SSRF | | | |
| API8:2023 Security Misconfiguration | | | |
| API9:2023 Improper Inventory Management | | | |
| API10:2023 Unsafe Consumption of APIs | | | |

"✅" means nothing was found in what was reviewed. It is not a guarantee: no review or tool fully covers the Top 10.

## 3. Findings

<!-- Write in stages: append findings in batches. Critical/High = full block. Medium/Low/Info = one table row each.
     Group repeats of one pattern ("+N similar at …"). No attack payloads — describe the input class instead. -->

### F-001 · {{Short title in plain words}} — {{Critical|High}}
- **Category:** {{A01:2025 Broken Access Control}} · {{API1:2023 BOLA}} · {{CWE-639}}
- **Location:** `{{path/to/file.ext:line}}`{{ (+N similar: file:line, …)}} · **Confidence:** {{Confirmed | Likely | Needs manual verification}} · **L×I:** {{H×H — factors}}
- **Evidence:**
  ```{{lang}}
  {{≤8 lines of the actual code; secrets redacted as abcd****}}
  ```
- **Impact:** {{what an attacker can concretely do in THIS app — one or two sentences}}
- **Fix:**
  ```{{lang}}
  {{concrete change for this codebase}}
  ```
- **Verify:** {{one line: test asserting safe behaviour, e.g. "user B token → GET /orders/<A's id> returns 404"}}

### Medium / Low / Info

| ID | Sev | Title | Category · CWE | Location | Fix (one line) |
|---|---|---|---|---|---|
| F-0xx | Medium | {{…}} | {{A02:2025 · CWE-942}} | `{{file:line}}` | {{…}} |

## 4. Remediation plan

| Priority | Findings | Effort | Action |
|---|---|---|---|
| Now (before deploy) | {{Critical + High}} | {{S/M/L}} | {{…}} |
| Next sprint | {{Medium}} | | |
| Backlog / hardening | {{Low, Info, ASVS L2 gaps}} | | |

**Prevent recurrence:** {{e.g. add semgrep + gitleaks + osv-scanner to CI, pre-commit gitleaks, authz integration tests with two users, dependency update policy}}

## 5. Scope, method and limitations

- **Stack:** {{languages/frameworks}} · **Entry points reviewed:** {{n routes / resolvers}} · **Approx. LOC:** {{n}}
- **Tools run:** {{tool version — ran/skipped/missing}} (details: `scanners.md`)
- **Runtime checks:** {{none | passive header/CORS/error checks on <url> | two-user authz test}}
- **Not covered / needs follow-up:** {{e.g. infra outside repo, prod config, third-party services, areas skimmed}}
- **Dismissed scanner leads:** {{n}} (false positives, listed in Appendix A)

## Appendix A — Dismissed scanner leads
| Tool | Rule | Location | Reason dismissed |
|---|---|---|---|

## Appendix B — Files
`inventory.md` · `attack-surface.md` · `scanners.md` · `scanner-findings.md` · `raw/`
