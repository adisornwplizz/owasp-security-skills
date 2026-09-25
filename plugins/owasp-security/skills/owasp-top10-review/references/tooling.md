# TOOLING — scanners, header baseline, ASVS, LLM Top 10, severity
Verified 2026-09-25 against primary sources (tool READMEs/docs, Homebrew formulae, OWASP repos). Versions = what Homebrew/PyPI/npm shipped on that date; pin them in the skill and re-verify periodically.

## 0. Ground rules for the skill
- Write all output to one folder (e.g. `OUT=.security-review; mkdir -p $OUT`). Prefer SARIF 2.1.0 (fits GitHub code scanning and most viewers) and fall back to JSON. Parse JSON for triage.
- **Never print raw secrets.** Use `gitleaks --redact`. Use `trufflehog --no-verification` unless the user agrees that candidate secrets may be sent to provider APIs to check them.
- **Network:** tell the user before a tool uploads package lists or rules (see the "Net" column). Offline options are listed per tool.
- **DAST only against localhost or the user's own staging, after explicit confirmation.** ZAP baseline is passive (spider + passive rules). ZAP full/API scans and nuclei `-dast` are active attacks: off by default, and each needs a separate opt-in. Never scan production or anything else.
- OWASP Top 10:2025 itself says tools "cannot comprehensively detect, test, or protect against the OWASP Top 10… OWASP discourages any claims of full coverage". The report must say this. Scanners support manual review; they don't replace it.
- The scanners themselves are part of the supply chain. **Trivy was compromised on 2026-03-19..22 (CVE-2026-33634, GHSA-69fq-xp46-6x23).** Malicious versions: binaries/images v0.69.4–0.69.6, `trivy-action` 0.0.1–0.34.2, `setup-trivy` v0.2.0–v0.2.5. The homebrew-core `trivy` formula (built from source) was not affected. Pin versions, pin Actions to commit SHAs, and don't `curl | bash` without checksum/cosign verification.

## 1. Free/OSS scanners
### 1.1 Matrix
| Tool (ver seen) | Kind | macOS install | Net | JSON / SARIF | Top 10:2025 | API Top 10:2023 |
|---|---|---|---|---|---|---|
| Semgrep CE 1.178 (PyPI) / 1.176 (brew) | SAST multi-lang | `brew install semgrep` or `pipx install semgrep` | Y: registry rules + metrics (`--metrics=off`) | `--json-output=f` / `--sarif-output=f` | A01 (part), A02, A04, A05, A07, A08, A10 (part) | API7, API8, API2/3 (part) |
| Opengrep 1.16.x | SAST (Semgrep fork, LGPL) | install.sh from releases (no brew formula) | N with local rules | `--json-output` / `--sarif-output` | same as Semgrep | same |
| gitleaks 8.30.1 | secrets | `brew install gitleaks` | N | `-f json\|sarif -r f` | A07 (CWE-798), A04 (CWE-321), A02 | API2, API8 |
| trufflehog 3.97.9 | secrets (+live verify) | `brew install trufflehog` | Y if verifying | `--json` / `--sarif` (stdout) | A07, A04, A02 | API2, API8 |
| osv-scanner 2.6.0 | SCA (all ecosystems) | `brew install osv-scanner` | Y (OSV API); offline DB option | `--format json\|sarif --output-file f` | A03 | API8 (unpatched) |
| trivy 0.74.0 | SCA + secrets + IaC | `brew install trivy` | Y (vuln DB/check bundle download) | `--format json\|sarif -o f` | A03, A02, A07 | API8 |
| npm/pnpm/yarn audit | SCA (JS) | ships with the package manager | Y (registry bulk advisory API) | `--json` | A03 | API8 |
| pip-audit 2.10.1 | SCA (Py) | `brew install pip-audit` | Y (PyPI/OSV) | `-f json` (no SARIF; CycloneDX available) | A03 | API8 |
| govulncheck 1.8.0 | SCA + reachability (Go) | `brew install govulncheck` | Y (vuln.go.dev); `-db file://` | `-format json\|sarif\|openvex` | A03 | API8 |
| composer audit | SCA (PHP) | `brew install composer` | Y (Packagist) | `--format=json` | A03 | API8 |
| dotnet package list | SCA (.NET) | .NET SDK | Y (NuGet) | `--format json` | A03 | API8 |
| OWASP dependency-check 13.0.0 | SCA (Java-centric) | `brew install dependency-check` | Y, heavy: NVD API (get a key), long first run | `--format JSON --format SARIF` | A03 | API8 |
| checkov 3.3.x | IaC/CI misconfig | `brew install checkov` | N for IaC (`--skip-download`) | `-o json\|sarif` | A02, A03, A08 | API8 |
| hadolint 2.15.1 | Dockerfile lint | `brew install hadolint` | N | `-f json\|sarif` | A02, A03 | API8 |
| zizmor 1.30.1 (optional) | GitHub Actions audit | `brew install zizmor` | `--offline` available | `--format=json\|sarif` | A08, A03 | — |
| ZAP (Docker) | DAST passive baseline | Docker Desktop, or `brew install --cask zap` | image pull; target local | `-J f.json` (+ `-r` html, `-w` md, `-x` xml) | A02, A07 (cookies), A10 (error leaks), A01 (CORS, part) | API8 |
| nuclei 3.11.1 | template DAST | `brew install nuclei` | Y (template update from GitHub; `-duc`) | `-jsonl -o f` / `-je f` / `-se f` | A02, A03 (known CVEs), A01 (exposures) | API8, API9 |
| bandit 1.9.4 | SAST Python | `brew install bandit` or `pipx install "bandit[sarif,toml]"` | N | `-f json\|sarif -o f` | A02, A04, A05, A07, A08, A10 | API7 (part) |
| gosec 2.29.0 | SAST Go | `brew install gosec` | N | `-fmt=json\|sarif -out=f` | A01, A04, A05, A07, A10 (G104) | API4 (timeouts) |
| brakeman | SAST Rails | `gem install brakeman` (not in homebrew-core) | N | `-o f.json` / `-o f.sarif` (by extension) | A01, A02, A04, A05 | API1 (unscoped find), API3 (mass assign) |
| eslint-plugin-security 4.0.1 | lint Node | `npm i -D eslint-plugin-security` | N | `-f json` / SARIF via `@microsoft/eslint-formatter-sarif` 3.1.0 | A05, A01 (fs paths), A04 | API4 (ReDoS) |
| SpotBugs 4.10.4 + FindSecBugs 1.14.0 | bytecode SAST Java/Kotlin | `brew install spotbugs` or Maven/Gradle plugin | N (after build) | `-sarif=f` / `-xml:withMessages=f` | A01, A02 (XXE), A04, A05, A07, A08 | API7 |
| Psalm 6.18 (taint) | SAST PHP | `composer require --dev vimeo/psalm` (brew: `psalm`) | N | `--report=f.sarif` / `.json` | A05, A01 | API7 (part) |

PHPStan 2.x (`brew install phpstan`) is a type checker with no taint analysis. Use Psalm `--taint-analysis` for security in PHP.

### 1.2 SAST — Semgrep CE / Opengrep
```bash
semgrep scan --metrics=off --config p/default --config p/owasp-top-ten --config p/secrets \
  --config p/<lang> --json-output=$OUT/semgrep.json --sarif-output=$OUT/semgrep.sarif .
```
- Registry rulesets confirmed to resolve on 2026-09-25: `p/default`, `p/owasp-top-ten`, `p/security-audit`, `p/secrets`, `p/cwe-top-25`, `p/javascript`, `p/typescript`, `p/nodejs`, `p/expressjs`, `p/react`, `p/python`, `p/django`, `p/flask`, `p/java`, `p/kotlin`, `p/golang`, `p/php`, `p/csharp`, `p/ruby`, `p/jwt`, `p/dockerfile`, `p/terraform`, `p/github-actions`. `p/nextjs` returns an **empty** ruleset (use `p/react` + `p/typescript`).
- **2025 mapping:** semgrep-rules metadata now carries 2025 tags next to 2021/2017 (e.g. `A05:2025 - Injection`, `A04:2025 - Cryptographic Failures`, `A08:2025 - Software or Data Integrity Failures`, `A01:2025`, `A07:2025`). Some rules are still tagged 2017-only (e.g. flask `debug-enabled`). Map through `extra.metadata.owasp` and `cwe`, and fall back to CWE→category when no 2025 tag exists. Many rules also carry `asvs:` metadata.
- CE analyses one function or file at a time (the README warns it "will miss many true positives"). Cross-file taint needs Semgrep Pro (`semgrep login`, `--pro`), which is out of scope for a free local run. `--error` exits 1 when there are findings. Filter with `--severity ERROR`.
- Rules are under the Semgrep Rules License v1.0: "only for your own internal business purposes", no redistribution or offering as a service. That is fine for a developer scanning their own code. Semgrep also ships an MCP server (`semgrep mcp`) and a Claude Code plugin.
- Opengrep (fork created after the licence change; claims Semgrep-rule compatibility) has no hosted registry. Point it at local rules instead (`git clone https://github.com/opengrep/opengrep-rules`, described as a fork "for research, testing & benchmarking"): `opengrep scan -f opengrep-rules/<lang> --taint-intrafile --sarif-output=$OUT/opengrep.sarif .`

### 1.3 Secrets
```bash
gitleaks git --redact -f sarif -r $OUT/gitleaks-history.sarif .     # full git history (git log -p)
gitleaks dir --redact -f json  -r $OUT/gitleaks-tree.json .         # working tree incl. untracked files
gitleaks git --pre-commit --staged --redact                          # pre-commit hook mode
trufflehog git file://. --no-verification --no-update --json > $OUT/trufflehog.json
trufflehog filesystem . --no-verification --no-update --sarif > $OUT/trufflehog.sarif
```
- gitleaks v8.19.0 deprecated `detect` and `protect` in favour of `git`/`dir`/`stdin`. The old commands are hidden but still work. Exit code is 1 on leaks (`--exit-code`). Use `--baseline-path` to suppress findings that are already known.
- trufflehog `--results=verified,unknown` (and `--fail` → exit 183) only mean something when verification runs, and verification calls third-party APIs with the found credential. Default to off. A verified live key counts as Critical.
- Betterleaks (MIT, released 2026-03, by the original gitleaks author; `brew install betterleaks`, v1.8.1) is an emerging alternative. Not verified as a drop-in replacement for the gitleaks CLI or config.

### 1.4 SCA (A03 Software Supply Chain Failures)
```bash
osv-scanner scan source -r --format sarif --output-file $OUT/osv.sarif .   # all lockfiles, recursive
osv-scanner scan source -r --format json  --output-file $OUT/osv.json .
osv-scanner --offline-vulnerabilities --download-offline-databases -r .    # local DB (`--offline` = zero network)
trivy fs --scanners vuln,secret,misconfig --format sarif -o $OUT/trivy-fs.sarif .   # add --severity HIGH,CRITICAL --exit-code 1 to gate
npm audit --json --omit=dev > $OUT/npm-audit.json        # --audit-level=high sets the exit threshold; also: npm audit signatures
pnpm audit --json --prod > $OUT/pnpm-audit.json          # pnpm ≥11 uses /-/npm/v1/security/advisories/bulk
yarn npm audit --all --recursive --json > $OUT/yarn-audit.ndjson   # Yarn Berry; Yarn 1: yarn audit --json
pip-audit -r requirements.txt -f json -o $OUT/pip-audit.json      # or: pip-audit --locked . (pyproject/pylock)
govulncheck -format sarif ./... > $OUT/govulncheck.sarif          # exits 0 in json/sarif mode, so parse output
composer audit --locked --format=json > $OUT/composer-audit.json  # --no-dev, --abandoned=report
dotnet package list --vulnerable --include-transitive --format json > $OUT/nuget.json   # .NET ≤9: dotnet list package ...
dependency-check --project app --scan . --format JSON --format SARIF --out $OUT --nvdApiKey "$NVD_API_KEY"
```
- osv-scanner exit codes: 0 = clean, 1 = vulns found, 128 = no packages found, 127 = general error. It sends package name, version and hash to api.osv.dev. For npm/Maven, `osv-scanner fix` gives guided remediation (experimental).
- **pip-audit security model:** "If you wouldn't `pip install` it, you should not `pip audit` it." It resolves requirements in a temporary venv, which can build sdists. Use `--no-deps`/`--disable-pip` with fully pinned, hashed requirements.
- NuGet Audit runs on every `dotnet restore` (SDK 8+, warnings NU1901–NU1904). Default `NuGetAuditMode` is `all` for .NET 10+ targets and `direct` for older ones.
- dependency-check: without an NVD key updates are "extremely slow". Sonatype OSS Index now requires a token and is disabled automatically without one. Use `--failOnCVSS 7` to gate. Prefer osv-scanner for speed and use dependency-check as a second opinion for Java.

### 1.5 IaC / container / CI config
```bash
trivy config --format sarif -o $OUT/trivy-config.sarif .            # Dockerfile, K8s, Terraform, Helm, CloudFormation
checkov -d . --quiet --compact --skip-download -o cli -o sarif --output-file-path console,$OUT/checkov.sarif
checkov -d . --quiet --skip-download -o json > $OUT/checkov.json    # --soft-fail keeps exit code 0
hadolint -f sarif Dockerfile > $OUT/hadolint.sarif                  # -t error = failure threshold
zizmor --offline --format=sarif .github/workflows/ > $OUT/zizmor.sarif   # unpinned actions, injection, excessive permissions
```

### 1.6 DAST — own local or staging app only, after explicit user confirmation
```bash
# ZAP baseline: spider (1 min default) + passive rules only, "doesn't perform any actual attacks"
docker run --rm -v "$(pwd)/$OUT":/zap/wrk/:rw -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://host.docker.internal:3000 -J zap-baseline.json -r zap-baseline.html -I
#   Linux: add --add-host=host.docker.internal:host-gateway. Docker Hub alias: zaproxy/zap-stable.
#   -j = Ajax spider for SPAs, -m <min> = spider minutes, -c <conf> = per-rule IGNORE/WARN/FAIL. Don't use the legacy owasp/zap2docker-* image names.
#   zap-api-scan.py -t <openapi-url> -f openapi|graphql|soap  → includes ACTIVE scan: opt-in, staging only.
# nuclei "safe profile": passive-ish detection templates, low rate, no fuzz/DAST/code/AI
nuclei -u http://localhost:3000 -tags misconfig,exposure,tech,headers \
  -etags intrusive,dos,fuzz,bruteforce,default-login -rl 10 -c 5 -duc -jsonl -o $OUT/nuclei.jsonl -se $OUT/nuclei.sarif
```
- nuclei's default ignore list already skips `dos, local, fuzz, bruteforce, txt-service`. Also exclude `intrusive` (622 templates) and `default-login`, which attempts logins. Never add `-dast`, `-code`, `-headless` with untrusted templates, or `-ai` (sends a prompt to a cloud service). Only use signed official templates (`-dut` disables unsigned ones).

### 1.7 Language-specific SAST
```bash
bandit -r . -x ./tests,./.venv -f sarif -o $OUT/bandit.sarif          # SARIF needs bandit[sarif]; -f json also works
gosec -fmt=sarif -out=$OUT/gosec.sarif -no-fail -exclude-generated ./...
brakeman -q --no-exit-on-warn -o $OUT/brakeman.json -o $OUT/brakeman.sarif
npx eslint -c eslint.config.js -f @microsoft/eslint-formatter-sarif -o $OUT/eslint.sarif .   # config: [pluginSecurity.configs.recommended]
spotbugs -textui -effort:max -low -pluginList findsecbugs-plugin-1.14.0.jar -sarif=$OUT/spotbugs.sarif target/classes
mvn com.github.spotbugs:spotbugs-maven-plugin:check -Dspotbugs.sarifOutput=true   # with the findsecbugs <plugin> in the pom
./vendor/bin/psalm --taint-analysis --report=$OUT/psalm.sarif
```
- eslint-plugin-security v4 (2026) is flat-config first (`module.exports=[pluginSecurity.configs.recommended]`, eslintrc uses `plugin:security/recommended-legacy`). The README warns it "finds a lot of false positives", so treat it as hotspots. Gradle: `spotbugsPlugins 'com.h3xstream.findsecbugs:findsecbugs-plugin:1.14.0'`. Limit output to `<Bug category="SECURITY"/>` with an include filter. Psalm needs PHP ≥ 8.2.

### 1.8 What the tools will NOT find (manual review is mandatory)
- **Authorization logic**: A01 / API1 BOLA, API3 BOPLA (field-level), API5 BFLA. Check with benign two-user tests: user A's token requesting user B's object should return 403/404.
- **A06 Insecure Design, API6 sensitive business flows, API4 business-level rate limits, A09 logging and alerting** (no SAST coverage), **A10** (only fragments such as swallowed errors, e.g. bandit B110, gosec G104), **API9 inventory** (compare routes against the OpenAPI spec), **API10 unsafe consumption** (review trust in third-party API responses).

## 2. Security headers & cookies baseline (2026)
Sources: OWASP HTTP Headers Cheat Sheet (CS), OWASP Secure Headers Project (OSHP) `ci/headers_add.json` (last updated 2026-09-13), REST Security CS for APIs, ASVS 5.0.0 V3.
| Header | Recommended value | Scope | ASVS 5.0 | Notes |
|---|---|---|---|---|
| Content-Security-Policy | Strict: `script-src 'nonce-{RANDOM}' 'strict-dynamic'; object-src 'none'; base-uri 'none'` (or hash-based) plus `frame-ancestors 'none'` | HTML | V3.4.3 (L2), V3.4.6 frame-ancestors (L2), V3.4.7 report (L3) | CS fallback: `default-src 'self'; frame-ancestors 'self'; form-action 'self'`. OSHP value: `default-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests`. Report with `report-to` (`report-uri` is deprecated; send both). |
| CSP for APIs | `frame-ancestors 'none'` | JSON | V3.4.6 | REST CS |
| Strict-Transport-Security | `max-age=63072000; includeSubDomains; preload` | all (HTTPS) | V3.4.1 (L1: ≥1 yr; L2+: includeSubDomains), V3.7.4 preload list (L3) | OSHP omits `preload`. Only add `preload` if you will submit the domain to the list. |
| X-Content-Type-Options | `nosniff` | all | V3.4.4 (L2) | |
| Content-Type | exact type with charset, e.g. `text/html; charset=UTF-8`, `application/json` | all with body | V4.1.1 (L1) | |
| Referrer-Policy | `strict-origin-when-cross-origin` (CS) or `no-referrer` (OSHP) | all | V3.4.5 (L2) | Either value passes. |
| Permissions-Policy | disable unused features, e.g. `geolocation=(), camera=(), microphone=()` | HTML | — | OSHP has a longer deny-all list |
| Cross-Origin-Opener-Policy | `same-origin` (or `same-origin-allow-popups`) | HTML | V3.4.8 (L3) | |
| Cross-Origin-Embedder-Policy | `require-corp` | HTML | — | Can break third-party embeds; recommend, don't require. |
| Cross-Origin-Resource-Policy | `same-site` (CS) or `same-origin` (OSHP) | resources/API | V3.5.8 (L3) (or Sec-Fetch-* checks) | |
| Access-Control-Allow-Origin | fixed value or allowlisted Origin; `*` only for non-sensitive data | API | V3.4.2 (L1) | Reflecting any Origin together with `Allow-Credentials: true` is a finding. |
| Cache-Control | `no-store` on sensitive responses (OSHP: `no-store, max-age=0`) | auth'd/API | — | `no-cache` still stores the response. |
| Clear-Site-Data | `"cache","cookies","storage"` | logout response | — | OSHP |
| X-Frame-Options | `DENY` | HTML | superseded by V3.4.6 | Legacy; keep for old browsers. Superseded by CSP `frame-ancestors`. |
| X-XSS-Protection | omit, or `0` | — | — | Deprecated and can *create* XSS. Flag `1; mode=block` as Info. |
| Expect-CT, Public-Key-Pins | don't send | — | — | Deprecated; remove. |
| X-Permitted-Cross-Domain-Policies / X-DNS-Prefetch-Control | `none` / `off` | optional | — | OSHP |
| **Remove** | `Server` (or a generic value), `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `SourceMap`, framework/version headers | all | V13.4.x | OSHP `headers_remove.json` lists 88 headers |

**Cookies** (Session Management CS; ASVS V3.3):
`Set-Cookie: __Host-SessionID=<v>; Secure; HttpOnly; SameSite=Strict; Path=/`
- `Secure` on every cookie, and use a `__Secure-` name if not `__Host-` (V3.3.1, L1). Use the `__Host-` prefix (requires Secure, no `Domain`, `Path=/`) unless the cookie must be shared across hosts (V3.3.3, L2). `HttpOnly` on anything scripts don't need, and session tokens only via `Set-Cookie` (V3.3.4, L2).
- `SameSite`: session cookies explicitly `Strict` (preferred) or `Lax`. Never `None` without `Secure`, and don't rely on browser defaults. SameSite adds defence in depth but doesn't replace CSRF tokens (V3.3.2, L2).
- Prefer non-persistent session cookies (no `Max-Age`/`Expires`). Don't store tokens/JWTs in `localStorage`/`sessionStorage`. Missing Secure/HttpOnly = CWE-614/CWE-1004, filed under **A02:2025**.
- New `__Http-` / `__Host-Http-` prefixes (require HttpOnly) are documented by MDN, but browser support is still emerging. Optional; don't flag their absence.

Quick check (benign): `curl -sI https://localhost:3000/ | grep -iE 'content-security|strict-transport|x-content-type|referrer|permissions|cross-origin|x-frame|set-cookie|server|x-powered'`. The ZAP baseline covers most of these passively.

## 3. OWASP ASVS
- **Latest: ASVS 5.0.0, released 2025-05-30** (live at Global AppSec EU Barcelona). The repo README on 2026-09-25 still names 5.0.0 as latest stable; the next target is patch **5.0.1**, not yet released. 345 requirements in 17 chapters: 70 L1, 183 new at L2 (253 cumulative), 92 new at L3.
- Cite requirements as `v5.0.0-<chapter>.<section>.<req>` (e.g. `v5.0.0-8.2.2`), because IDs changed completely from 4.0.3.

| Ch | Name (reqs: L1/L2/L3 new) | Ch | Name |
|---|---|---|---|
| V1 | Encoding and Sanitization (8/19/3) | V10 | OAuth and OIDC (5/24/7) |
| V2 | Validation and Business Logic (4/7/2) | V11 | Cryptography (3/11/10) |
| V3 | Web Frontend Security (8/11/12) | V12 | Secure Communication (3/6/3) |
| V4 | API and Web Service (2/8/6) | V13 | Configuration (1/12/8) |
| V5 | File Handling (4/5/4) | V14 | Data Protection (2/7/4) |
| V6 | Authentication (13/22/12) | V15 | Secure Coding and Architecture (3/10/8) |
| V7 | Session Management (6/12/1) | V16 | Security Logging and Error Handling (0/16/1) |
| V8 | Authorization (4/3/6) | V17 | WebRTC (0/7/5) |
| V9 | Self-contained Tokens (4/3/0) | | |

- **Levels (ASVS 5.0 "What is the ASVS"):**
  - L1 = "minimum requirements… critical starting point", about 20% of requirements.
  - L2 = "**Most applications should be striving to achieve this level**", about 70% cumulative.
  - L3 = highest assurance, the remaining ~30%.
  - The ASVS itself doesn't mandate a level ("an early-stage startup… Level 1… a bank… Level 3"). **Skill default: assess against L1 as the must-pass floor and report L2 gaps as recommendations. Use L3 when the app handles payments, health data or high-value data.**
- **Mapping Top 10:2025 → ASVS: there is no official requirement-level mapping.** Top 10:2025 recommends ASVS as the verifiable standard ("the only acceptable choice for tool vendors"). Each category page only links chapters under References: A01→V8, A02→V13, A04→V11/V12/V14, A09→V16, A10→V16.5. Some links still use ASVS 4.x names (A05→"V5 Input Validation and Encoding"; A03 links the old AASVS V1). The mapping below is **ours** (chapter level, unofficial):
  - Top 10:2025: A01→V8 (+V1.3.6 SSRF, V3.3.2/V3.5 CSRF/origin). A02→V13, V3.4, V4.1. A03→V15.1/V15.2 (SBOM V15.1.2, remediation timeframes V15.1.1/V15.2.1, dependency confusion V15.2.4). A04→V11, V12, V14. A05→V1 (+V5 file). A06→V2.1/V2.3, V15.1. A07→V6, V7, V9, V10. A08→V1.5 deserialization, V3.6 SRI, V15.2. A09→V16.1–V16.4. A10→V16.5, V15.3.
  - API 2023: API1/API3/API5→V8 (V8.2.2 IDOR/BOLA, L1). API2→V6, V9, V10. API4/API6→V2.4 anti-automation, V2.3. API7→V1.3.6. API8→V13, V3.4. API9→V15.1 documentation/inventory, V13. API10→V2.2 input validation and V1 (treat third-party API data as untrusted), plus V12.3/V13.2 for service-to-service TLS and config.

## 4. OWASP Top 10 for LLM Applications (optional note when the app has LLM features)
- **Current edition: 2026.** OWASP GenAI Security Project published it in Aug 2026 (resource page dated 2026-08-03). Weighting was 75% expert vote and 25% incident data. Order confirmed by CSA and Invicti write-ups, consistent with Help Net Security (2026-08-06). Get the full text from the official PDF at genai.owasp.org.

| 2026 | Name | 2025 equivalent |
|---|---|---|
| LLM01 | Prompt Injection (now includes cross-modal) | LLM01 |
| LLM02 | Sensitive Information Disclosure | LLM02 |
| LLM03 | Excessive Agency | LLM06 |
| LLM04 | Supply Chain | LLM03 |
| LLM05 | Data and Model Poisoning (absorbs fine-tuning subversion) | LLM04 |
| LLM06 | Unbounded Consumption | LLM10 |
| LLM07 | Misinformation | LLM09 |
| LLM08 | Hidden Context Exposure (renamed/broadened System Prompt Leakage) | LLM07 |
| LLM09 | Vector and Embedding Weaknesses | LLM08 |
| LLM10 | Improper Output Handling | LLM05 |

- The 2025 list (still what genai.owasp.org/llm-top-10 shows) is LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.
- Also relevant for tool-using agents: **OWASP Top 10 for Agentic Applications for 2026** (published 2025-12-09, IDs ASI01–ASI10) and the new Agent Control Standard (Sep 2026). In code, look at: LLM output passed to `eval`/SQL/HTML/shell (web A05 plus LLM10:2026), tool permissions and human approval (LLM03), secrets or PII in prompts and system prompts (LLM02/LLM08), and token/cost limits (LLM06, web API4).

## 5. Severity rubric (for the report)
Use **OWASP Risk Rating Methodology (likelihood × impact)** for code-review findings: it works without a live exploit and is OWASP-native. Use **CVSS v4.0** only for dependency CVEs: copy the advisory's score and label it `CVSS-B` (base only) as the spec's nomenclature requires. Don't hand-compute CVSS for design flaws.
- CVSS v4.0 bands (FIRST spec v1.2): None 0.0 · Low 0.1–3.9 · Medium 4.0–6.9 · High 7.0–8.9 · Critical 9.0–10.0.
- OWASP RRM: likelihood and impact are each scored 0–9 from factors (threat agent: skill, motive, opportunity, size; vulnerability: ease of discovery, ease of exploit, awareness, intrusion detection; technical impact: C/I/A/accountability; business impact: financial, reputation, non-compliance, privacy). The average is rated LOW (<3), MEDIUM (3–<6), HIGH (6–9). Overall severity:

| Likelihood \ Impact | LOW | MEDIUM | HIGH |
|---|---|---|---|
| **HIGH** | Medium | High | **Critical** |
| **MEDIUM** | Low | Medium | High |
| **LOW** | Note (Info) | Low | Medium |

**Simplified inputs for the skill** (state which factors applied, so ratings are reproducible):
- *Likelihood HIGH:* reachable unauthenticated or by any logged-in user, trivially triggered, found by public scanners/templates, or a secret/credential is present. *MEDIUM:* needs an authenticated low-privilege user, specific state, or chaining. *LOW:* needs an admin or insider, unusual config, or a non-default path. Where CISA KEV or a public exploit exists for a dependency CVE, move likelihood up one step.
- *Impact HIGH:* RCE, auth bypass, cross-tenant or other users' data (BOLA/BFLA), bulk PII/credential exposure, payment/business-flow abuse, secret with production scope. *MEDIUM:* limited data exposure, stored XSS in a low-privilege area, CSRF on non-critical actions, DoS of one feature. *LOW:* information leaks (versions, stack traces without data), missing hardening headers, verbose errors.
- Anchors:
  - **Critical:** SQLi/command injection on a public route; live cloud/API key in git history; missing authz on `/admin/*`; IDOR on `/api/orders/{id}`.
  - **High:** SSRF to metadata/internal network; JWT `alg=none` or unverified signature; vulnerable dependency with CVSS ≥ 7 on a reachable code path.
  - **Medium:** missing CSP/HSTS on an authenticated app; session cookie without HttpOnly/Secure; no rate limit on login.
  - **Low:** `X-Powered-By` present; X-XSS-Protection enabled; missing Permissions-Policy.
  - **Info:** best-practice gaps and unverified hotspots.
- Normalizing scanner output (the rubric overrides it): Semgrep `ERROR/WARNING/INFO` → start at High/Medium/Low. ZAP risk `High/Medium/Low/Informational` → same. nuclei and Trivy/OSV already use critical..low (from CVSS). gitleaks/trufflehog have no severity → default High, Critical if verified live or if it's a production credential. Always record confidence (Confirmed / Likely / Needs manual verification) separately from severity.

## Sources
- Tool docs/READMEs (raw GitHub, 2026-09-25): semgrep/semgrep README; semgrep/semgrep-rules rule metadata; docs.semgrep.dev/cli-reference; semgrep.dev/c/p/<ruleset>; semgrep.dev/legal/rules-license; opengrep/opengrep and opengrep/opengrep-rules READMEs; gitleaks/gitleaks README + cmd/git.go; trufflesecurity/trufflehog README; google/osv-scanner README + docs/usage.md, docs/output.md, docs/offline-mode.md (https://google.github.io/osv-scanner/); aquasecurity/trivy README; https://trivy.dev/latest/docs/configuration/reporting/; bridgecrewio/checkov README; https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html; hadolint/hadolint README; projectdiscovery/nuclei README; projectdiscovery/nuclei-templates .nuclei-ignore + TEMPLATES-STATS.md; PyCQA/bandit README + doc/source/start.rst; securego/gosec README; presidentbeef/brakeman README; eslint-community/eslint-plugin-security (npm registry); spotbugs/spotbugs docs/running.rst; spotbugs-maven-plugin SpotBugsMojo; find-sec-bugs wiki Maven-configuration; vimeo/psalm docs/security_analysis; pypa/pip-audit README; golang/vuln cmd/govulncheck/doc.go; zizmorcore/zizmor docs/usage.md
- Homebrew formulae: https://github.com/Homebrew/homebrew-core/tree/main/Formula (versions above)
- https://www.zaproxy.org/docs/docker/baseline-scan/ · https://www.zaproxy.org/docs/docker/about/ · https://www.zaproxy.org/docs/docker/api-scan/
- https://docs.npmjs.com/cli/v11/commands/npm-audit · https://pnpm.io/cli/audit · https://yarnpkg.com/cli/npm/audit · https://getcomposer.org/doc/03-cli.md · https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-package-list · https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages
- https://dependency-check.github.io/DependencyCheck/dependency-check-cli/arguments.html · https://github.com/dependency-check/DependencyCheck
- Trivy compromise: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23 · https://www.microsoft.com/en-us/security/blog/2026/03/24/detecting-investigating-defending-against-trivy-supply-chain-compromise/ · https://github.com/aquasecurity/trivy/releases/tag/v0.72.0
- Betterleaks: https://www.bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks/
- Headers/cookies: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html · .../Content_Security_Policy_Cheat_Sheet.html · .../Session_Management_Cheat_Sheet.html · .../REST_Security_Cheat_Sheet.html · https://owasp.org/www-project-secure-headers/ (repo OWASP/www-project-secure-headers ci/headers_add.json, ci/headers_remove.json) · https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie
- ASVS: https://github.com/OWASP/ASVS (README; v5.0.0 CSV 5.0/docs_en/…_5.0.0_en.csv; 5.0/en/0x03-What-is-the-ASVS.md) · https://owasp.github.io/www-project-application-security-verification-standard/ · https://owasp2025globalappseceu.sched.com/event/1whCc/introducing-the-50-release-of-the-asvs
- Top 10:2025: https://owasp.org/Top10/2025/ (repo OWASP/Top10 2025/docs/en: A01–A10 pages, 0x03_2025-Establishing_a_Modern_Application_Security_Program.md) · API 2023: https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- LLM: https://genai.owasp.org/llm-top-10/ · https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ · https://labs.cloudsecurityalliance.org/research/csa-research-note-owasp-genai-top10-2026-agent-control-stand/ · https://www.invicti.com/blog/web-security/owasp-llm-top-10-2026-whats-new · https://www.helpnetsecurity.com/2026/08/06/owasp-2026-llm-top-10-released/ · https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- Severity: https://www.first.org/cvss/v4-0/specification-document · https://owasp.org/www-community/OWASP_Risk_Rating_Methodology
