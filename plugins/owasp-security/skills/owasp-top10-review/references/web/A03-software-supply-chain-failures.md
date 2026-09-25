## A03:2025 – Software Supply Chain Failures
**Edition notes:**
- Ranked #3 in 2025. Expanded from **A06:2021 Vulnerable and Outdated Components**, which came from A9:2013 "Using Components with Known Vulnerabilities". The scope now covers every compromise in building, distributing or updating software: dependencies (direct and transitive), build systems, CI/CD, artifact and container registries, developer workstations, and IDEs and their extensions. Known CVEs are only part of it.
- #1 in the community survey (50% ranked it first). The contributed data is thin: 6 CWEs mapped and only 11 CVEs. It has the highest average weighted exploit score (8.17) and impact score (5.23) of any category. Average incidence is 5.72%, maximum 9.56%, average coverage 27.47%.
- Inconsistencies in the official page: the introduction says "5 CWEs" but the score table says 6. The background text gives the average incidence as 5.19% but the table says 5.72%. The mapped-CWE list prints "CWE-447 Use of Obsolete Function", but the correct ID is **CWE-477** (CWE-447 is an unrelated UI weakness).
- **Boundary with A08:2025.** A03 covers *which* third-party code, tools and pipelines you depend on and *how you manage them*: known-vulnerable, outdated, EOL, unmaintained, typosquatted or malicious components, weak patch and SBOM processes, and a build or CI/CD pipeline that is compromised or not hardened. A08 is the *lower-level code/data check*: does the application or pipeline accept code or data across a trust boundary without verifying its integrity or authenticity? Examples are missing SRI, checksums or signatures, insecure deserialization, mass assignment and unsigned cookies. Quick test: "we pulled in a bad or old component, or our pipeline was weak" is A03. "We used or executed something without verifying it" is A08. Package signing and CI integrity fall under both. Report under A03 when the finding is about process or inventory, and under A08 when it is about a missing verification in code or config.

### What it is (issue)
A supply chain failure is a breakdown or compromise in the process of building, distributing or updating software. It usually comes from vulnerable or malicious third-party code, tools or dependencies. Components run with the application's privileges. One vulnerable library (Log4Shell, Struts CVE-2017-5638, React2Shell CVE-2025-55182) or one malicious package version installed by a developer or CI runner can mean RCE or stolen credentials. Since 2025 the main threat has been self-propagating worms that steal tokens: Shai-Hulud (Sep 2025), Shai-Hulud 2.0 (Nov 2025, 796 packages, preinstall hook), and the TanStack/"Mini Shai-Hulud" waves (May 2026). The TanStack wave abused `pull_request_target` cache poisoning and then published through trusted publishing, so the malicious versions carried *valid* provenance.

### Root causes
- No complete inventory (SBOM) of direct **and transitive** dependencies, runtimes, base images, CI actions and IDE extensions, so nobody knows what is exposed when an advisory ships.
- Non-deterministic installs: no lockfile committed, `npm install`/`composer update` run in CI, floating ranges (`*`, `latest`, `^`, `+`, `LATEST`), mutable tags (`@v4`, `:latest`) for GitHub Actions and container images.
- Install-time code execution is trusted by default: npm ≤11 `preinstall`/`postinstall`, pip sdist builds, Composer plugins, Gradle and Maven plugins.
- Newly published versions are installed immediately (no cooldown), which is when worm-published versions are live.
- Patching is treated as a quarterly change-control task. There are no documented remediation SLAs and no automated SCA gate, and audit failures get suppressed (`|| true`, broad ignore lists).
- Registry and resolution trust is ambiguous: `--extra-index-url`, unscoped internal package names (dependency confusion), git/URL dependencies, HTTP repositories, TLS verification disabled.
- The CI/CD pipeline is weaker than production: long-lived publish tokens, over-privileged `GITHUB_TOKEN`, no separation of duties, unpinned third-party actions, secrets available to untrusted PR code.
- EOL or unmaintained runtimes and frameworks (Node ≤20, Python ≤3.9, .NET 6/7, PHP ≤8.1) and abandoned packages that will never get a fix.
- Dependencies are added on trust, including names suggested by AI tools ("slopsquatting") and typosquats, with no vetting step.

### Key CWEs
Official 2025 mapping (★ = most relevant for web/API developers):
- ★ **CWE-1395** Dependency on Vulnerable Third-Party Component. Primary; covers known CVEs in libraries, runtimes and images.
- ★ **CWE-1104** Use of Unmaintained Third Party Components. Covers abandoned or EOL packages and runtimes.
- ★ **CWE-1357** Reliance on Insufficiently Trustworthy Component. Covers malicious or typosquatted packages, untrusted registries and unvetted actions.
- ★ **CWE-1329** Reliance on Component That is Not Updateable. Covers vendored or forked copies, bundled binaries and firmware.
- ★ **CWE-477** Use of Obsolete Function. Covers deprecated or removed APIs (for example `crypto.createCipher`, `mysql_*`). The official page misprints it as CWE-447.
- CWE-1035 2017 Top 10 A9: Using Components with Known Vulnerabilities (a category entry, kept for continuity).
- Adjacent but mapped to A08: CWE-494 (download without integrity check), CWE-829/830 (untrusted functionality or CDN), CWE-506/509 (malicious code or worm).

### How to detect — code review
**Stack-agnostic, where to look:** manifests plus lockfiles; `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.circleci/`; `Dockerfile*`, `docker-compose*.yml`, Helm charts and Terraform; registry config (`.npmrc`, `.yarnrc.yml`, `pnpm-workspace.yaml`, `bunfig.toml`, `pip.conf`, `uv.toml`, `nuget.config`, `settings.xml`, `composer.json` `config`); `dependabot.yml` and `renovate.json`; `.devcontainer/`, `.vscode/extensions.json`.
- **Lockfile committed?** `git ls-files | rg '(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|uv\.lock|poetry\.lock|Pipfile\.lock|pylock\..*toml|composer\.lock|go\.sum|packages\.lock\.json|gradle\.lockfile)$'`. A deployable app with no match is a finding.
- **Non-frozen installs in CI or Docker:** `rg -nP '\b(npm (i|install)\b(?!.* -g)|yarn install(?!.*--(immutable|frozen-lockfile))|pnpm (i|install)\b(?!.*--frozen-lockfile)|composer (update|require)\b|pip install (?!.*--require-hashes)(?!-e)|dotnet restore(?!.*--locked-mode))' .github .gitlab-ci.yml Dockerfile* Makefile scripts/`
- **Actions not pinned to a full SHA:** `rg -nP 'uses:\s*(?!\./|docker://)[^@\s]+@(?![0-9a-f]{40}\b)\S+' .github/`. Also check for a missing top-level `permissions:` block, or `write-all` (`rg -n 'permissions:\s*write-all' .github/`).
- **Images without a digest, or using latest:** `rg -nP '^\s*FROM\s+(?!scratch\b)(?![^\s]*@sha256:)\S+' -g 'Dockerfile*'` and `rg -n 'image:\s*[^@\s]+(:latest)?\s*$' -g '*compose*.y*ml' -g '*.yaml'`.
- **Pipe-to-shell installers (overlaps A08/CWE-494):** `rg -nP '(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b'`
- **Suppressed or disabled auditing:** `rg -n '(audit[^\n]*\|\|\s*true|--audit-level[= ](critical|none)|--no-audit|NuGetAudit>\s*false|NU190[1-4]|ignore-unfixed|IgnoredVulns|\.trivyignore)'`. Accept ignores only if each has a reason and an expiry (`ignoreUntil` in `osv-scanner.toml`).
- **No update automation:** there is no `.github/dependabot.yml` or `renovate.json`, or the one present has no `github-actions` or `docker` ecosystem entry.
- **EOL runtime pins** (checked 2026-09 against endoflife.date): Node ≤20 (20 EOL 2026-04-30); Python ≤3.9 (3.10 EOL 2026-10-31); .NET 6/7 (8 and 9 EOL 2026-11-10); PHP ≤8.1 (8.2 security ends 2026-12-31); Go: only the latest two releases get security fixes.

**Node (Express / NestJS / Next.js)**
- Loose, URL or git specs: `rg -nP '"[@\w./-]+"\s*:\s*"(\*|latest|x|>=?\s*\d[^"]*|https?://[^"]+|git(\+\w+)?:[^"]+|github:[^"]+)"' package.json`. HTTP-URL dependencies are how PhantomRaven's 126 packages hid their payloads ("0 dependencies" to scanners).
- `.npmrc` risks: `rg -n '^(registry=http:|strict-ssl\s*=\s*false|//[^ ]+:_authToken=[^$])' .npmrc`. Internal packages that are not scoped, or scopes not mapped with `@org:registry=`, allow dependency confusion.
- Dependencies with install hooks: `npm query ':attr(scripts, [postinstall])'` (repeat for `preinstall` and `install`). On npm ≥12 use `npm install-scripts ls`, and on pnpm use `pnpm ignored-builds`.
- High-impact framework versions: `rg -n '"(next|react-server-dom-(webpack|turbopack|parcel))"\s*:' package.json`. Flag Next.js below 15.2.3 / 14.2.25 / 13.5.9 (CVE-2025-29927 middleware authorization bypass) and RSC packages below 19.0.1 / 19.1.2 / 19.2.1 (CVE-2025-55182, CVSS 10).
- Vendored browser libraries (`public/js/jquery-*.js`, `vendor/`) are invisible to lockfile SCA. Run `retire` over them.

**Python (Django / FastAPI / Flask)**
- Unpinned requirements (lines with no `==`): `rg -nv '(==|^\s*#|^\s*-|^\s*$)' requirements*.txt`
- Index confusion and TLS bypass: `rg -n '(--extra-index-url|--trusted-host|index-strategy\s*=\s*"unsafe-(best|first)-match")' requirements*.txt pip.conf pyproject.toml uv.toml`. uv defaults to `first-index`; pip merges all indexes.
- No hashes enforced at deploy: `pip install -r` without `--require-hashes`, or `uv sync` without `--locked`/`--frozen`.
- EOL interpreters: `rg -n '(FROM\s+python:3\.[0-9]\b|requires-python\s*=\s*"[^"]*3\.[0-9]\b|python_requires)'`

**Java (Spring Boot)**
- Dynamic versions: `rg -n '<version>\s*(LATEST|RELEASE|\[[^\]]*,\s*\))' pom.xml` and `rg -nP "['\"][\w.-]+:[\w.-]+:(\+|[\d.]+\+|latest\.(release|integration))['\"]" -g 'build.gradle*'`
- Insecure or implicit repositories: `rg -n '(<url>http://|url\s*=?\s*["(]?\s*["'\'']http://|allowInsecureProtocol\s*=\s*true|mavenLocal\(\))' pom.xml -g '*.gradle*'`
- Notorious components to check against the lockfile or dependency tree: `log4j-core` <2.17.1, `struts2-core`, `commons-text` <1.10, `snakeyaml` <2.0, and a `spring-boot-starter-parent` version past OSS support. Run `mvn dependency:tree` or `./gradlew dependencies`.
- No Gradle dependency locking or verification (`gradle.lockfile`, `gradle/verification-metadata.xml`).

**Go**
- `rg -n '^\s*(replace\s|.*=>\s*\.\.?/)' go.mod` (forks and local paths bypass the checksum DB). `rg -n '(GOSUMDB=off|GONOSUMDB|GONOSUMCHECK|GOINSECURE|GOFLAGS=[^\n]*(-mod=mod|-insecure))'`
- Unpinned tool installs in CI: `rg -n 'go (install|run|get) \S+@latest'`. A missing `go.sum`, or a `go` or `toolchain` directive older than the two supported releases.

**PHP (Laravel)**
- `rg -n '"(\*|dev-(master|main)|>=[^"]*)"' composer.json` and `rg -n '"minimum-stability"\s*:\s*"dev"|"secure-http"\s*:\s*false|"allow-plugins"\s*:\s*true' composer.json`
- `composer update` in deploy scripts or Dockerfiles (should be `composer install --no-dev` from `composer.lock`). A `laravel/framework` major past security support (see the laravel.com/docs releases table).

**.NET (ASP.NET Core)**
- Floating versions: `rg -n 'Version="[^"]*\*' -g '*.csproj' -g 'Directory.Packages.props'`. Audit turned off: `rg -n '<NuGetAudit>\s*false|<NoWarn>[^<]*NU190[1-4]' -g '*.csproj' -g '*.props'`
- `nuget.config` with more than one `<add key=` source and no `<packageSourceMapping>` (dependency confusion). EOL TFMs: `rg -n '<TargetFrameworks?>[^<]*(net[5-7]\.0|netcoreapp)' -g '*.csproj'`. Missing `RestorePackagesWithLockFile`.

**False positives:** ranges in a *library's* manifest are normal if the app's lockfile pins exact versions. Judge the lockfile, not the manifest. A CVE in a devDependency or test-only package is lower severity unless it runs in CI with secrets (build tools do). govulncheck and other reachability-aware tools can show a vulnerable symbol is never called: downgrade it, but still schedule the upgrade. First-party actions (`actions/*`, `github/*`) on tags are lower risk than third-party ones, but the Trivy compromise (Mar 2026: 76 of 77 `trivy-action` tags force-pushed) shows any tag can be moved. `FROM` a digest-pinned internal base image is fine. `npm install` in a local dev README is fine; in CI or a Dockerfile it is not.

### How to detect — runtime (safe, own app only)
- Version disclosure, then advisory lookup: `curl -sI http://localhost:3000 | rg -i '^(server|x-powered-by|x-aspnet(mvc)?-version|x-generator):'`. Look up the versions on osv.dev.
- Browser-side libraries: `curl -s http://localhost:3000/ | rg -o '<script[^>]+src="[^"]+"'`. List third-party and CDN URLs and their versions. Run `npx retire --path ./dist` (or `./public`) on the built assets.
- Leaked manifests (they help attackers fingerprint): `for p in package.json package-lock.json yarn.lock composer.lock composer.json requirements.txt go.mod .npmrc; do curl -s -o /dev/null -w "%{http_code} $p\n" http://localhost:3000/$p; done`. Expect 404 everywhere.
- Built image and runtime: `trivy image --severity HIGH,CRITICAL myapp:dev`; `docker run --rm myapp:dev node -v` (or `python -V`, `java -version`, `dotnet --info`), then compare to EOL tables.
- Registry integrity of what is actually installed: `npm audit signatures` (registry signatures and provenance attestations); `pnpm audit signatures` (pnpm ≥11.1).
- Known-malicious versions in the resolved tree: `osv-scanner scan -r .` reports OSV `MAL-` advisories alongside CVEs.

### Tools
Commands checked against current docs (Sep 2026). Fail the build on the exit code.
- **npm:** `npm ci` then `npm audit --omit=dev --audit-level=high` (non-zero at ≥high). Also `npm audit signatures`; `npm query ':vuln([severity=critical])'`; `npm query ':outdated(major)'`; `npm sbom --sbom-format cyclonedx --omit dev > sbom.cdx.json`.
- **pnpm:** `pnpm audit --prod --audit-level high` (`--fix=update` on v11); `pnpm audit signatures`.
- **Yarn Berry:** `yarn npm audit --all --recursive --environment production --severity high`. Yarn classic: `yarn audit --groups dependencies --level high`.
- **Browser JS:** `npx retire --path ./public`.
- **Python:** `pip-audit -r requirements.txt --strict` (or `--require-hashes`); `pip-audit --locked .` (pylock) or `pip-audit .` (pyproject); `pip-audit -f cyclonedx-json > sbom.cdx.json`. `uv audit` (uv preview, June 2026, OSV-backed); `UV_MALWARE_CHECK=1 uv sync` blocks OSV `MAL-` packages before install.
- **Go:** `govulncheck ./...` (source, call-graph reachability; exit 1 on findings in text mode); `govulncheck -mode binary ./bin/app`; `-format sarif` for code scanning (exit 0).
- **PHP:** `composer audit --locked --no-dev --abandoned=fail` (`abandoned` defaults to `fail` since 2.7). Composer ≥2.9 blocks advisory-affected versions on `update` (`audit.block-insecure: true`). 2.10 (May 2026) adds a `config.policy` block and blocks malware by default.
- **.NET:** `dotnet list package --vulnerable --include-transitive` (SDK ≤9), or `dotnet package list --vulnerable` (.NET 10 SDK; `dotnet package update --vulnerable` fixes). Restore-time NuGetAudit: `NuGetAuditMode=all` (default for net10.0+), warnings NU1901–NU1904.
- **Java:** `mvn org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=7 -DnvdApiKey=$NVD_API_KEY`; Gradle `id("org.owasp.dependencycheck") version "13.0.0"` then `./gradlew dependencyCheckAnalyze`; CLI `dependency-check.sh --project app --scan . --format HTML --failOnCVSS 7 --nvdApiKey "$NVD_API_KEY"`. Version 12.1.0+ is mandatory (NVD API change). Get an NVD API key or updates are extremely slow.
- **Polyglot:** `osv-scanner scan -r .`, `osv-scanner scan -L package-lock.json`, `osv-scanner scan image myapp:dev`, `--format sarif|json|cyclonedx-1-5|spdx-2-3`. `osv-scanner fix` runs package-manager scripts, so do not use it on untrusted repos. `trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL --exit-code 1 .`; `trivy image --ignore-unfixed myapp:dev`; `grype dir:.` or `grype sbom:./sbom.cdx.json`.
- **SBOM:** `syft scan dir:. -o cyclonedx-json=sbom.cdx.json -o spdx-json=sbom.spdx.json`; `syft myapp:dev -o cyclonedx-json`; `trivy fs --format cyclonedx --output sbom.cdx.json .`; `npx @cyclonedx/cyclonedx-npm --omit dev --output-file sbom.cdx.json`; `cyclonedx-py environment -o sbom.cdx.json` (also `requirements`, `poetry`, `pipenv`); `mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom`. Upload to OWASP Dependency-Track for continuous monitoring.
- **CI/CD and Actions:** `pinact run` (rewrites to `@<sha> # vX.Y.Z`; `pinact run --check` in CI); `zizmor .github/workflows` (audits `unpinned-uses`, `known-vulnerable-actions`, `dangerous-triggers`, `excessive-permissions`, `cache-poisoning`, `artipacked`, `unpinned-images`, `dependabot-cooldown`, `use-trusted-publishing`); CodeQL `actions/unpinned-tag`; OpenSSF Scorecard `scorecard --repo=github.com/<org>/<repo> --checks=Pinned-Dependencies,Token-Permissions,Dangerous-Workflow,Maintained,Vulnerabilities`. GitHub also has an org/repo "require full-length commit SHA" setting in the allowed-actions policy (Aug 2025).
- **Containers and IaC:** `hadolint Dockerfile` (DL3006 untagged, DL3007 `latest`); `trivy config .`; `docker scout cves myapp:dev`; `semgrep scan --config p/dockerfile --config p/github-actions .`
- **Outdated or unmaintained:** `npm outdated`, `composer outdated --direct`, `pip list --outdated`, `go list -m -u all`, `dotnet list package --outdated`, `mvn versions:display-dependency-updates`; Scorecard `Maintained`; endoflife.date.
- Note: the Trivy binary and `trivy-action` were themselves compromised in Mar 2026 (v0.69.4 malicious). Pin scanner actions by SHA and verify binaries (`cosign`/sigstore) like any other dependency.

### Fix / remediation
**GitHub Actions: pin, least privilege, no secrets for untrusted code**
```yaml
# BAD
on: pull_request_target          # fork code + secrets
jobs: { build: { runs-on: ubuntu-latest, steps: [
  { uses: actions/checkout@v4 }, { uses: someorg/deploy-action@main }, { run: npm install } ] } }
# GOOD
on: pull_request
permissions: { contents: read }                     # raise per job only when needed
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<full-40-char-sha> # vX.Y.Z  (Dependabot keeps SHA+comment updated)
        with: { persist-credentials: false }
      - run: npm ci && npm audit --omit=dev --audit-level=high
# Publishing: npm trusted publishing (OIDC) instead of stored NPM_TOKEN. Note that valid provenance
# proves where a package was built, not that it is benign (TanStack, May 2026).
```
**Node install hardening**
```ini
# .npmrc  (npm <=11 runs dependency lifecycle scripts by default)
ignore-scripts=true          # then `npm rebuild <pkg>` only for vetted native deps
min-release-age=3            # days; npm >=11.10 (older npm silently ignores it)
@acme:registry=https://npm.internal.example/   # scope internal packages (dependency confusion)
# npm >=12 (Jul 2026): dependency scripts are blocked unless listed in package.json "allowScripts"
#   -> `npm install-scripts ls` / `npm install-scripts approve sharp`; git and remote-tarball deps default to "none".
```
```yaml
# pnpm-workspace.yaml  (pnpm 11: minimumReleaseAge defaults to 1440 and strictDepBuilds to true)
minimumReleaseAge: 4320            # minutes
allowBuilds: { esbuild: true }     # pnpm 11; pnpm 10 used onlyBuiltDependencies
# Yarn 4.10+: .yarnrc.yml -> enableScripts: false, npmMinimalAgeGate: 4320 (minutes)
# Bun: runs only trustedDependencies' scripts; bunfig.toml [install] minimumReleaseAge = 259200 (seconds)
```
**Python: pinned and hashed**
```text
# BAD requirements.txt:   django>=4.2   plus   --extra-index-url https://pypi.internal.example/simple
# GOOD: uv pip compile requirements.in --generate-hashes -o requirements.txt   (or pip-compile --generate-hashes)
django==X.Y.Z --hash=sha256:<...>
# deploy: pip install --require-hashes -r requirements.txt   |  uv sync --locked
# cooldown: uv --exclude-newer "7 days" (uv >=0.9.17) | pip --uploaded-prior-to (pip >=26.0)
```
**Container base image and build**
```dockerfile
# BAD
FROM node:latest
RUN curl -fsSL https://get.example.com/tool.sh | sh
COPY . .
RUN npm install
# GOOD
FROM node:24-bookworm-slim@sha256:<digest>   # Node 24 LTS; digest-pinned, bumped by Dependabot/Renovate
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY . .
USER node
```
**.NET / Composer / Go quick fixes**
```xml
<!-- Directory.Build.props; CI runs: dotnet restore --locked-mode -->
<PropertyGroup><RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
  <NuGetAuditMode>all</NuGetAuditMode><WarningsAsErrors>$(WarningsAsErrors);NU1903;NU1904</WarningsAsErrors></PropertyGroup>
```
Composer: commit `composer.lock`, deploy with `composer install --no-dev --no-interaction`, and set `"allow-plugins": {"vendor/plugin": true}` explicitly. Go: keep `GOSUMDB` and `GOFLAGS=-mod=readonly` at their defaults, run `go mod verify` in CI, and remove `replace` directives before release.

**Dependabot with cooldown (also covers Actions and Docker digests)**
```yaml
version: 2
updates:
  - { package-ecosystem: npm,            directory: /, schedule: { interval: weekly }, cooldown: { default-days: 7 } }
  - { package-ecosystem: github-actions, directory: /, schedule: { interval: weekly } }
  - { package-ecosystem: docker,         directory: /, schedule: { interval: weekly } }
```

### Best-practice checklist
- [ ] Documented, risk-based remediation time frames for vulnerable components and routine updates (ASVS 5.0 **15.1.1**), and no component past those time frames (**15.2.1**).
- [ ] An SBOM (CycloneDX/SPDX) generated per build and monitored continuously (Dependency-Track or OSV), and components come only from pre-defined, trusted, maintained repositories (**15.1.2**).
- [ ] All transitive dependencies resolve from the expected repository. Internal packages are scoped or mapped (npm scopes, NuGet `packageSourceMapping`, uv `first-index`, no `--extra-index-url`), so dependency confusion is not possible (**15.2.4**).
- [ ] "Risky components" documented (**15.1.4**) and sandboxed or isolated (**15.2.5**). No dev, test or sample code shipped to production (**15.2.3**).
- [ ] Lockfile committed. CI uses frozen installs (`npm ci`, `pnpm i --frozen-lockfile`, `yarn install --immutable`, `uv sync --locked`, `pip --require-hashes`, `composer install`, `dotnet restore --locked-mode`, `go mod verify`).
- [ ] SCA runs on every PR and on a schedule (new CVEs land on unchanged code), fails at ≥High, and every ignore has a reason and an expiry.
- [ ] Install scripts off by default with an allowlist (npm `ignore-scripts` or npm 12 `allowScripts`, pnpm `allowBuilds`, Yarn `enableScripts: false`, Bun `trustedDependencies`). A release-age cooldown of 1–7 days is configured.
- [ ] Third-party GitHub Actions pinned to full commit SHAs (org policy enforced). `permissions:` is read-only by default. No `pull_request_target` or `workflow_run` running fork code with secrets. OIDC or trusted publishing replaces long-lived tokens.
- [ ] Base images pinned by digest, minimal or distroless, rebuilt on patch releases. Runtimes and frameworks are on supported (non-EOL) lines.
- [ ] Unused dependencies removed (`depcheck`/`knip`, `go mod tidy`, `composer why`). New dependencies are vetted: registry existence, maintainers, age, downloads, repo link (covers AI-suggested names).
- [ ] Developer workstations and CI hardened: MFA, branch protection, required reviews (no single person can push to production), secrets in a vault (**13.3.1**), IDE extensions allow-listed.
- [ ] Staged or canary rollouts, plus an incident playbook for "a malicious version was installed" (rotate npm, GitHub and cloud tokens; check for persistence).

### Severity guidance
- **Critical:** a known-exploited (CISA KEV) or RCE/auth-bypass CVE in a reachable production dependency or runtime (Log4Shell, React2Shell CVE-2025-55182 in an RSC app, Next.js CVE-2025-29927 when middleware does auth). A known-malicious package version in the lockfile or installed on CI or dev machines (Shai-Hulud IOCs); treat it as an incident and rotate secrets. A CI workflow where a third-party action on a mutable ref, or fork PR code, can reach publish or deploy credentials.
- **High:** a High-severity CVE in a production dependency with a plausible path. EOL runtime or framework in production (no security fixes). No lockfile or non-frozen installs for a deployed service. HTTP or `--trusted-host` registries. Unscoped internal packages resolvable from public registries. Floating `:latest` base image in production.
- **Medium:** vulnerable dependency not reachable (per govulncheck or reachability analysis) or devDependency-only on a CI runner without secrets. Third-party actions on tags with a read-only token. Install scripts enabled with no allowlist. No SCA gate in CI. Abandoned package with no known CVE. Audit suppressions with no expiry.
- **Low:** outdated but supported versions. Missing SBOM or cooldown or update automation where a good lockfile and SCA exist. Version disclosure in headers (cross-ref A02).

### Sources
- https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/ and https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A03_2025-Software_Supply_Chain_Failures.md
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/0x00_2025-Introduction.md
- https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md (ASVS 5.0.0, https://github.com/OWASP/ASVS/releases)
- https://cheatsheetseries.owasp.org/cheatsheets/NPM_Security_Cheat_Sheet.html, .../Software_Supply_Chain_Security_Cheat_Sheet.html, .../CI_CD_Security_Cheat_Sheet.html, .../Vulnerable_Dependency_Management_Cheat_Sheet.html, .../Dependency_Graph_SBOM_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/1395.html (CWE 4.20), https://cwe.mitre.org/data/definitions/1104.html, /1357.html, /1329.html, /477.html
- https://docs.npmjs.com/cli/v11/commands/npm-audit, https://docs.npmjs.com/cli/v11/commands/npm-sbom, https://docs.npmjs.com/cli/v11/using-npm/config
- https://github.com/npm/cli/blob/latest/CHANGELOG.md (npm 12.0.0, 2026-07-08: allowScripts default-deny, allow-git/allow-remote=none), https://github.com/npm/cli/blob/latest/docs/lib/content/commands/npm-install-scripts.md
- https://github.blog/changelog/2025-12-09-npm-classic-tokens-revoked-session-based-auth-and-cli-token-management-now-available/
- https://pnpm.io/cli/audit, https://pnpm.io/blog/releases/11.0, https://yarnpkg.com/cli/npm/audit, https://bun.com/docs/pm/lifecycle
- https://craigory.dev/blog/2026-05-29/package-manager-release-cooldown/, https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down.html, https://www.brandonpugh.com/til/node/package-version-cooldown/
- https://github.com/pypa/pip-audit, https://astral.sh/blog/uv-audit, https://cyclonedx-bom-tool.readthedocs.io/en/latest/usage.html, https://github.com/CycloneDX/cyclonedx-node-npm
- https://google.github.io/osv-scanner/usage/, https://google.github.io/osv-scanner/output/
- https://trivy.dev/latest/docs/references/configuration/cli/trivy_filesystem/, https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck
- https://getcomposer.org/doc/03-cli.md, https://github.com/composer/composer/blob/main/doc/06-config.md, https://github.com/composer/composer/blob/main/CHANGELOG.md
- https://learn.microsoft.com/en-us/nuget/concepts/auditing-packages
- https://github.com/dependency-check/DependencyCheck (README, cli arguments, maven configuration), https://github.com/dependency-check/dependency-check-gradle
- https://github.com/anchore/syft
- https://docs.github.com/en/actions/reference/security/secure-use, https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/, https://github.com/suzuki-shunsuke/pinact, https://docs.zizmor.sh/audits/
- https://securitylabs.datadoghq.com/articles/shai-hulud-2.0-npm-worm/, https://unit42.paloaltonetworks.com/monitoring-npm-supply-chain-attacks/, https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/, https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem
- https://thehackernews.com/2025/10/phantomraven-malware-found-in-126-npm.html, https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components, https://www.offsec.com/blog/cve-2025-29927/
- https://endoflife.date/nodejs, https://endoflife.date/python, https://endoflife.date/dotnet, https://endoflife.date/php
