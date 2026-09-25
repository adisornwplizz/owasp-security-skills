# Category map, filing rules and editions

Verified 2026-09-25. Sources: top10.owasp.org/2025 (formerly owasp.org/Top10/2025; final, with the release-candidate label removed on 2025-12-24, and only typo fixes since. Source: github.com/OWASP/Top10 `2025/docs/en`),
owasp.org/API-Security 2023 (still the current API edition, with no newer edition or RC), ASVS 5.0.0 (2025-05-30, still latest).

## OWASP Top 10:2025 (web)

| ID | Name | 2021 origin | CWEs | ASVS 5.0 chapters (unofficial) | API 2023 overlap | Reference |
|---|---|---|---|---|---|---|
| A01 | Broken Access Control | A01 + SSRF (A10:2021) merged in | 40 | V8, V1.3.6 (SSRF), V3.5 (CSRF/origin) | API1, API3 (read), API5, API7 | web/A01-broken-access-control.md |
| A02 | Security Misconfiguration | A05 (up from #5) | 16 | V13, V3.4 headers, V3.3 cookies, V1.5.1 XXE | API8, API9 | web/A02-security-misconfiguration.md |
| A03 | Software Supply Chain Failures | NEW (expands A06:2021 Vulnerable & Outdated Components) | 6 | V15.1, V15.2 | API8 (unpatched), API9 | web/A03-software-supply-chain-failures.md |
| A04 | Cryptographic Failures | A02 | 32 | V11, V12, V14 | API2 (JWT signature, hashing) | web/A04-cryptographic-failures.md |
| A05 | Injection (incl. XSS) | A03 | 37 | V1 | API10 (tainted 3rd-party data), API8:2019 dropped | web/A05-injection.md |
| A06 | Insecure Design | A04 | 39 | V2, V15.1 | API4, API6 | web/A06-insecure-design.md |
| A07 | Authentication Failures | A07 (renamed from Identification & Auth Failures) | 36 | V6, V7, V9, V10 | API2 | web/A07-authentication-failures.md |
| A08 | Software or Data Integrity Failures | A08 | 14 | V1.5 deserialization, V3.6 SRI, V15.2 | API3 (write/mass assignment), API10 | web/A08-software-or-data-integrity-failures.md |
| A09 | Security Logging & Alerting Failures | A09 (renamed from ...Monitoring Failures) | 5 | V16.1–V16.4 | (API10:2019 dropped) | web/A09-security-logging-and-alerting-failures.md |
| A10 | Mishandling of Exceptional Conditions | NEW | 24 | V16.5, V15.3 | API4 (partial), API8 (verbose errors) | web/A10-mishandling-of-exceptional-conditions.md |

The OWASP Top 10 is an awareness document, not a compliance standard. For verification or compliance, OWASP points to
**ASVS 5.0** (Level 1 = minimum, Level 2 = "most applications should be striving to achieve this level", Level 3 = payments/health/high value).
OWASP also discourages claims that tools fully cover the Top 10.

## OWASP API Security Top 10:2023

| ID | Name | Primary 2025 mapping | Reference |
|---|---|---|---|
| API1 | Broken Object Level Authorization (BOLA/IDOR) | A01 | api/API1-bola.md |
| API2 | Broken Authentication | A07 (JWT signature/hashing → A04) | api/API2-broken-authentication.md |
| API3 | Broken Object Property Level Authorization (excessive exposure + mass assignment) | A01 (read) + A08 (write, CWE-915) | api/API3-bopla.md |
| API4 | Unrestricted Resource Consumption | none direct; A06 / A10 closest | api/API4-unrestricted-resource-consumption.md |
| API5 | Broken Function Level Authorization (BFLA) | A01 | api/API5-bfla.md |
| API6 | Unrestricted Access to Sensitive Business Flows | A06 | api/API6-sensitive-business-flows.md |
| API7 | Server Side Request Forgery | A01 (CWE-918) | api/API7-ssrf.md |
| API8 | Security Misconfiguration | A02 (+A10 errors, A04 cleartext) | api/API8-security-misconfiguration.md |
| API9 | Improper Inventory Management | none direct; A02 / A06 / A03 closest | api/API9-improper-inventory-management.md |
| API10 | Unsafe Consumption of APIs | A08 + A05 (+A04, A07, A10) | api/API10-unsafe-consumption-of-apis.md |

Runtime test convention for API checks: localhost or staging only, seeded data, test users A and B (same tenant),
C (other tenant) and an admin. Never production or real paid providers.

## Filing rules (one finding = one primary category)

Pick the primary category from the **root-cause CWE** in the official 2025 lists. Add the API ID and secondary categories as tags.
Never count the same code defect twice.

| Situation | Primary | Why / tag |
|---|---|---|
| IDOR / missing ownership or tenant check | A01 (CWE-639/862/863) | + API1 |
| Admin/privileged route without role check | A01 (CWE-862/285) | + API5 |
| Response returns fields the caller shouldn't see (password hash, internal flags, other users' PII) | A01 (CWE-200/201/359) | + API3 |
| Mass assignment (client can set `role`, `isAdmin`, `price`, `ownerId`) | A08 (CWE-915) | + API3 |
| SSRF (server fetches user-supplied URL) | A01 (CWE-918) | + API7 |
| CSRF on state-changing cookie-auth route | A01 (CWE-352) | |
| Path traversal / directory listing | A01 (CWE-22 / CWE-548) | |
| CORS policy config (reflect any origin, `*` + credentials) | A02 (CWE-942) | + API8 |
| Origin/Referer validation logic | A07 (CWE-346) | |
| Debug mode / dev error pages / default config shipped | A02 (CWE-489/16) | + API8 |
| Code that returns `err.stack` / `str(e)` / exception text to clients | A10 (CWE-209/550) | + API8 |
| Swallowed exception, fail-open auth/authz in `catch`, unchecked return value, partial transaction | A10 (CWE-636/390/252/460) | |
| Missing security headers, cookie flags (Secure/HttpOnly) | A02 (CWE-16/614/1004) | |
| XXE / entity expansion | A02 (CWE-611/776) | |
| Vulnerable, unmaintained or unpinned dependency; lockfile missing; CI actions unpinned | A03 (CWE-1395/1104/1357) | |
| CDN script without SRI; download-and-execute without integrity; insecure deserialization | A08 (CWE-830/494/502) | |
| Hard-coded password / API key / default credentials | A07 (CWE-798/259/1392) | + A04 if it is a crypto key (CWE-321) |
| Weak password hashing (MD5/SHA1/unsalted, low work factor) | A04 (CWE-916/759/760) | + API2 |
| JWT `alg:none`, signature not verified, weak HS256 secret | A04 (CWE-347/326) | + API2, A07 |
| JWT `exp`/`aud`/`iss` not validated; session fixation; no logout invalidation | A07 (CWE-613/384/287) | + API2 |
| No brute-force protection on login/OTP/reset | A07 (CWE-307) | + API2 |
| Weak password policy | A07 (CWE-521) | |
| Plaintext password storage / cleartext sensitive data at rest | A06 (CWE-256/312) per 2025 list | + A04 |
| Cleartext transport (http, TLS verify disabled) | A04 (CWE-319) / A07 (CWE-295 cert validation) | |
| Insecure randomness for tokens/IDs | A04 (CWE-330/338) | |
| SQL/NoSQL/command/template injection, XSS | A05 | |
| Unrestricted file upload | A06 (CWE-434) | |
| Race condition / TOCTOU on balance, coupon, stock | A06 (CWE-362) | + API6 |
| Client-side enforcement of price/limits/workflow | A06 (CWE-602/841) | + API6 |
| No pagination cap, payload/timeout limits, unbounded 3rd-party spend (SMS/LLM) | A06 (closest; CWE-770/400 not in 2025) | + API4 |
| Bot-able sensitive business flow (signup, checkout, referral) | A06 (CWE-799) | + API6 |
| Secrets/PII in logs; log injection | A09 (CWE-532/117) | |
| Security events not logged / no alerting | A09 (CWE-778/223) | |
| Old API versions, undocumented/debug endpoints still routed | A02 (closest) | + API9 |
| Trusting 3rd-party API responses (no validation, follows redirects, no timeout) | A08 (CWE-345) / A05 (CWE-20) | + API10 |

## LLM features

If the app calls an LLM (openai, anthropic, langchain, ai-sdk, etc.), add a short section that checks against the
**OWASP Top 10 for LLM Applications**. The 2026 edition came out in Aug 2026. Its order below comes from secondary
write-ups (CSA, Invicti); confirm against the official PDF at genai.owasp.org. 2026 IDs:
LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain,
LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure,
LLM09 Vector and Embedding Weaknesses, LLM10 Improper Output Handling.
In code, check for:
- LLM output reaching SQL, shell, `eval`, HTML or URLs. File this under A05 + LLM10.
- Untrusted text concatenated into system prompts. File under LLM01.
- Tool/agent permissions and human approval for side effects. File under LLM03.
- Secrets or PII in prompts. File under LLM02/LLM08.
- Token and cost caps. File under LLM06 + API4.

## Full CWE → 2025 category lists
(Also embedded in `scripts/summarize_findings.py`.)
- A01: 22 23 36 59 61 65 200 201 219 276 281 282 283 284 285 352 359 377 379 402 424 425 441 497 538 540 548 552 566 601 615 639 668 732 749 862 863 918 922 1275
- A02: 5 11 13 15 16 260 315 489 526 547 611 614 776 942 1004 1174
- A03: 477 (the official page lists it as "447", a typo) 1035 1104 1329 1357 1395
- A04: 261 296 319 320 321 322 323 324 325 326 327 328 329 330 331 332 334 335 336 337 338 340 342 347 523 757 759 760 780 916 1240 1241
- A05: 20 74 76 77 78 79 80 83 86 88 89 90 91 93 94 95 96 97 98 99 103 104 112 113 114 115 116 129 159 470 493 500 564 610 643 644 917
- A06: 73 183 256 266 269 286 311 312 313 316 362 382 419 434 436 444 451 454 472 501 522 525 539 598 602 628 642 646 653 656 657 676 693 799 807 841 1021 1022 1125
- A07: 258 259 287 288 289 290 291 293 294 295 297 298 299 300 302 303 304 305 306 307 308 309 346 350 384 521 613 620 640 798 940 941 1390 1391 1392 1393
- A08: 345 353 426 427 494 502 506 509 565 784 829 830 915 926
- A09: 117 221 223 532 778
- A10: 209 215 234 235 248 252 274 280 369 390 391 394 396 397 460 476 478 484 550 636 703 754 755 756
