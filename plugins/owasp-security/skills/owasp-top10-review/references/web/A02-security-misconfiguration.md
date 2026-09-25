## A02:2025 – Security Misconfiguration
**Edition notes:** Moved up from #5 (A05:2021) to #2. The official page says "100% of the applications tested were found to have some form of misconfiguration." Stats: 16 CWEs mapped (2021: 20), max incidence 27.70%, avg incidence 3.00%, avg coverage 52.35%, 719,084 occurrences, 1,375 CVEs. XXE (CWE-611, standalone A04:2017) and XML entity expansion (CWE-776) stay here. New in the mapping: CWE-5 and CWE-489 (Active Debug Code). Moved out: the error-message CWEs (CWE-209, 550, 756) are mapped to **A10:2025 Mishandling of Exceptional Conditions**, and default or hard-coded credentials (CWE-1392/1393, CWE-798) to **A07:2025**. Even so, the A02 text still lists "stack traces" and "default accounts" as misconfiguration. Practical split: debug flags, dev error pages and default creds shipped in deploy config go in A02; exception-handling code goes in A10; credential logic goes in A07. Directory listing (CWE-548) is mapped to A01. The reference standard is ASVS 5.0.0 **V13 Configuration**, plus V3 (headers/cookies/CORS), 1.5.1 (XXE) and 16.5 (errors). API overlap: API8:2023 Security Misconfiguration (TLS, verbs, CORS, cache headers, error detail) and API9:2023 Improper Inventory (exposed docs, old versions).

### What it is (issue)
The system (app, framework, server, container, cloud service) is set up insecurely even when the code itself is correct. Typical cases: debug mode or dev error pages in production, unnecessary features/endpoints/ports enabled, default accounts, permissive CORS, missing security headers or cookie flags, XML parsers that resolve external entities, secrets in config or env that leak, and cloud storage open to the internet. Attackers find these cheaply with automated scans. The impact ranges from fingerprinting to full takeover (an interactive debugger, heap dumps, exposed `.env`).

### Root causes
- Framework and platform defaults favor developer convenience: debug pages, `Secure`-less cookies, DTD-resolving XML parsers, permissive sample CORS, open admin consoles.
- No enforced separation between dev and prod config. Prod depends on remembering an env var (`NODE_ENV`, `DEBUG`, `APP_DEBUG`, `ASPNETCORE_ENVIRONMENT`, `GIN_MODE`), and missing values fall back to insecure defaults.
- Configuration is spread across layers (app, reverse proxy, CDN, container, orchestrator, cloud IAM) with no single owner. One layer strips or overrides another's headers.
- Secrets live in config files, image layers, compose files, or client-exposed env prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`).
- Features accumulate and are never removed: actuator, pprof, Swagger UI, GraphQL introspection, H2 console, debug toolbars, sample apps.
- Config is copy-pasted from tutorials (`origin: '*'` + credentials, `csrf.disable()`, `DEBUG=True`).
- No automated verification in CI (IaC/Dockerfile scanning, header tests, `check --deploy`). Hardening is not repeatable.
- Backward compatibility wins over security (legacy TLS, security features disabled after upgrades).

### Key CWEs
All 16 mapped (★ = most relevant for web/API devs):
- ★ CWE-489 Active Debug Code
- ★ CWE-611 Improper Restriction of XML External Entity Reference (XXE)
- ★ CWE-776 Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
- ★ CWE-942 Permissive Cross-domain Policy with Untrusted Domains (CORS)
- ★ CWE-614 Sensitive Cookie in HTTPS Session Without 'Secure' Attribute
- ★ CWE-1004 Sensitive Cookie Without 'HttpOnly' Flag
- ★ CWE-526 Exposure of Sensitive Information Through Environmental Variables
- ★ CWE-260 Password in Configuration File / CWE-13 ASP.NET Misconfiguration: Password in Configuration File
- CWE-547 Use of Hard-coded, Security-relevant Constants; CWE-315 Cleartext Storage of Sensitive Information in a Cookie
- CWE-16 Configuration; CWE-15 External Control of System or Configuration Setting
- CWE-5 J2EE Misconfiguration: Data Transmission Without Encryption; CWE-11 ASP.NET Misconfiguration: Creating Debug Binary; CWE-1174 ASP.NET Misconfiguration: Improper Model Validation

### How to detect — code review
**Stack-agnostic signals (where to look)**
- App config: `.env*`, `settings*.py`, `application*.yml|properties`, `appsettings*.json`, `web.config`, `config/*.php`, `next.config.*`, `launchSettings.json`. Check that the prod profile sets debug off, a generic error handler, secure cookies, CORS allowlist, HSTS, and that docs/admin endpoints are off.
- Security headers: is there a middleware (helmet, Django `SecurityMiddleware` + 6.0 CSP middleware, Spring Security headers, `UseHsts`) or proxy config (`add_header` in nginx) that sets CSP (with `frame-ancestors`), HSTS, `X-Content-Type-Options: nosniff`, Referrer-Policy? Are banners (`X-Powered-By`, `Server` version) removed?
- Cookies: every `Set-Cookie` for session/auth should be `Secure; HttpOnly; SameSite=Lax|Strict`, ideally with a `__Host-` prefix.
- XML parsing entry points (SOAP, SAML, SVG/DOCX/XLSX upload, RSS, XML-RPC): check how each parser is constructed.
- Exposed tooling: actuator, `/debug/pprof`, `expvar`, Swagger/OpenAPI, GraphQL introspection, H2 console, Telescope/Debugbar/Ignition, Django debug toolbar, phpinfo.
- Containers/IaC: Dockerfile `USER` missing (root), `ENV` secrets, `COPY . .` without `.dockerignore` (ships `.env`/`.git`), debug ports (`9229`, `5005`, `5678`, `--inspect=0.0.0.0`). Compose DB ports published with default passwords. K8s `privileged: true`, no `runAsNonRoot`. Terraform public buckets and `0.0.0.0/0` on admin/DB ports.
- Web server: `autoindex on;` (nginx), `Options +Indexes` (Apache), `server_tokens on`, TRACE enabled, docroot not pointing to the public directory.

**Node (Express / NestJS / Next.js)**
- CORS: `rg -n "origin:\s*(true|['\"]\*['\"])"` then check the same config for `credentials:\s*true`. The `cors` package's `origin: true` reflects the request Origin. Also `rg -n "Access-Control-Allow-Origin['\"],\s*req\.headers\.origin"`, and NestJS `enableCors\(\{[^}]*origin:\s*true`.
- Headers: missing `helmet(`; missing `app.disable('x-powered-by')` when helmet is absent. Next.js `poweredByHeader` not `false`; no `headers()` in `next.config.*`.
- Cookies: `rg -n "secure:\s*false|httpOnly:\s*false|sameSite:\s*['\"]none"`. express-session defaults to `secure: false` and no SameSite. MemoryStore in prod.
- Errors/debug: `rg -n "(err|error)\.stack"` in responses. Express's default handler includes the stack whenever `NODE_ENV !== 'production'`, so check that the deploy sets it. `--inspect` in start scripts.
- Secrets/env: `rg -n "(NEXT_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(SECRET|TOKEN|PASSWORD|PRIVATE|KEY)"`. Next.js `productionBrowserSourceMaps:\s*true`. Hard-coded `secret:\s*['\"]`.
- XXE: `rg -n "parseXml(String)?\([^)]*noent:\s*true"` (libxmljs).

**Python (Django / FastAPI / Flask)**
- Django: `rg -n "^\s*DEBUG\s*=\s*True|ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*|SECRET_KEY\s*=\s*['\"](django-insecure-)?"`. Check that `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS` and `SECURE_PROXY_SSL_HEADER` are set in prod. CORS: `CORS_ALLOW_ALL_ORIGINS\s*=\s*True` (legacy `CORS_ORIGIN_ALLOW_ALL`) combined with `CORS_ALLOW_CREDENTIALS = True` makes django-cors-headers echo any Origin.
- FastAPI/Starlette: `rg -U "allow_origins=\[\s*['\"]\*['\"]\s*\][\s\S]{0,200}allow_credentials=True"`. Starlette then echoes the request Origin with credentials. Also `FastAPI\([^)]*debug=True`. `/docs`, `/redoc`, `/openapi.json` are on by default: set `docs_url=None, redoc_url=None, openapi_url=None` for internal APIs.
- Flask: `rg -n "\.run\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1"` (Werkzeug interactive debugger). Flask defaults: `SESSION_COOKIE_SECURE=False`, `SESSION_COOKIE_SAMESITE=None`, `SECRET_KEY=None`. flask-cors `supports_credentials=True` without explicit `origins`.
- XML: `rg -n "from xml\.(etree|dom|sax)|import xml\.|lxml\.etree\.(fromstring|parse|XMLParser)"` on untrusted input. Prefer `defusedxml`. For lxml, flag `resolve_entities=True` or `no_network=False`.

**Java (Spring Boot)**
- `rg -n "management\.endpoints\.web\.exposure\.include\s*[=:]\s*['\"]?\*"`. Only `health` is exposed by default. `env`, `heapdump` and `configprops` are sensitive. Actuator is secured by default only if Spring Security is present and no custom `SecurityFilterChain` overrides it.
- `rg -n "server\.error\.include-(stacktrace|message|exception|binding-errors)\s*[=:]\s*(always|true)"` (Boot defaults are `never`/off).
- `rg -n "spring\.h2\.console\.enabled\s*[=:]\s*true|springdoc\.(swagger-ui|api-docs)\.enabled|^debug\s*[=:]\s*true"` in the prod profile.
- XXE: `rg -n "DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance|XMLInputFactory\.new(Default)?(Instance|Factory)|TransformerFactory\.newInstance|SchemaFactory\.newInstance"`, then confirm `disallow-doctype-decl`=true / `SUPPORT_DTD`=false. JDK parsers resolve DTDs by default.
- CORS: `allowedOriginPatterns\(\s*"\*"\s*\)` + `allowCredentials\(true\)` (Spring rejects `allowedOrigins("*")` with credentials, but patterns bypass that check). Security headers disabled: `rg -n "headers\(\s*\w+\s*->\s*\w+\.disable\(\)\)|headers\(\)\.disable\(\)"`.

**Go**
- `rg -n "_ \"net/http/pprof\"|\"expvar\""` (gosec G108) on a public listener. `http.FileServer(http.Dir(` serves directory listings and dotfiles (G111 flags `http.Dir("/")`).
- `gin.SetMode(gin.DebugMode)` or no `GIN_MODE=release` in deploy.
- Cookies: `http.Cookie{` without `Secure: true, HttpOnly: true, SameSite:` (G124).
- CORS (rs/cors): `AllowOriginFunc:\s*func\([^)]*\)\s*bool\s*\{\s*return true` or `AllowedOrigins:\s*\[\]string\{"\*"\}` together with `AllowCredentials:\s*true`.
- Errors: `rg -n "http\.Error\(w,\s*err\.Error\(\)|w\.Write\(\[\]byte\(err\.Error\(\)\)\)"`.
- XXE: `encoding/xml` does not resolve external entities, so the risk is low. Review cgo libxml2 bindings.

**PHP (Laravel)**
- `.env`/deploy: `rg -n "^APP_DEBUG=true|^APP_ENV=(local|dev)|^APP_KEY=\s*$"`. The web root must be `public/`, otherwise `.env` can be served.
- `config/cors.php`: `'allowed_origins' => ['*']` together with `'supports_credentials' => true`.
- `config/session.php`: `'secure'` must resolve to true in prod (`SESSION_SECURE_COOKIE=true`), `'http_only' => true`, `'same_site' => 'lax'|'strict'`.
- Dev tooling in prod: `laravel/telescope`, `barryvdh/laravel-debugbar` under `require` (not `require-dev`) or enabled in prod. `rg -n "phpinfo\(|display_errors\s*=\s*(On|1)"`.
- XXE: `rg -n "LIBXML_NOENT|LIBXML_DTDLOAD|LIBXML_DTDATTR"` in `simplexml_load_*`/`DOMDocument::load*`. PHP ≥8.0 with libxml2 ≥2.9 is safe by default unless these flags are set.

**.NET (ASP.NET Core)**
- `rg -n "UseDeveloperExceptionPage\(\)"` outside an `IsDevelopment()` block. `ASPNETCORE_ENVIRONMENT=Development` in Dockerfile/compose/prod settings. `"DetailedErrors":\s*true`.
- Legacy `web.config`: `<customErrors mode="Off"`, `<compilation debug="true"` (CWE-11), `enableVersionHeader` not false.
- Secrets: `rg -n "(Password|Pwd)=[^;\"]+" appsettings*.json web.config` (CWE-13/260). Use user-secrets or Key Vault.
- XXE: `rg -n "DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new XmlUrlResolver|ProhibitDtd\s*=\s*false"`.
- CORS: `rg -n "SetIsOriginAllowed\(\s*\w*\s*=>\s*true\)"` together with `AllowCredentials()` (Microsoft docs call it insecure). `AllowAnyOrigin()+AllowCredentials()` is rejected by the framework.
- Cookies/TLS: `CookieSecurePolicy\.(None|SameAsRequest)`. Missing `UseHsts()`/`UseHttpsRedirection()` in prod.

**False-positive notes**
- `DEBUG=True` or `secure: false` in files used only in dev (`settings/dev.py`, `.env.development`, `appsettings.Development.json`) is fine if the prod path overrides it. Trace what the deploy actually loads.
- `Access-Control-Allow-Origin: *` without credentials on public, non-sensitive, cookieless data is allowed (ASVS 3.4.2). The finding is `*` or reflection combined with credentials or sensitive data.
- Swagger or GraphQL introspection intentionally public for a public API is fine ("unless explicitly intended", ASVS 13.4.5, 4.3.2).
- pprof or actuator bound to an internal-only port or listener behind network policy has a lower risk (still note it).
- `.env.example` with placeholders is not a secret. XML parsers that only read build-time, trusted files: recommend hardening, severity Low.
- Parsers already hardened by a shared factory or helper: confirm by reading the helper.

### How to detect — runtime (safe, own app only)
Run the **production build and config** (e.g. `NODE_ENV=production`, `DEBUG=False`, `--spring.profiles.active=prod`, `ASPNETCORE_ENVIRONMENT=Production`) on localhost or staging.
- Headers: `curl -sI https://staging.example/ | grep -iE 'strict-transport|content-security|x-content-type|x-frame|referrer-policy|permissions-policy|cross-origin|server|x-powered-by|x-aspnet'`
- Cookies: `curl -si -X POST .../login -d '...' | grep -i '^set-cookie'`. Expect `Secure; HttpOnly; SameSite=` and a `__Host-` prefix.
- Error handling: send malformed input (`-H 'Content-Type: application/json' -d '{'`, `/api/items/not-a-number`, unknown route). Expect a generic message and correlation ID; no stack trace, SQL, file paths or framework version.
- Debug/admin exposure (expect 404 or 401): `/actuator`, `/actuator/env`, `/actuator/heapdump` (use `curl -I` only), `/debug/pprof/`, `/debug/vars`, `/h2-console`, `/telescope`, `/_debugbar`, `/__debug__/`, `/docs`, `/swagger-ui/`, `/v3/api-docs`, `/openapi.json`, `/phpinfo.php`, `/server-status`, `/.env`, `/.git/HEAD`, `/web.config`, `/*.map`.
- GraphQL introspection: `curl -s -X POST /graphql -H 'Content-Type: application/json' -d '{"query":"{__schema{queryType{name}}}"}'`. Expect it to be disabled in prod unless intended.
- Methods: `curl -si -X TRACE http://localhost:8080/` (expect 405). `curl -si -X OPTIONS` to list allowed methods.
- Directory listing: `curl -s http://localhost:8080/static/ | grep -i 'index of'`.
- CORS: `curl -si -H 'Origin: https://evil.example' .../api/me | grep -i '^access-control-allow-(origin|credentials)'`. Reflected origin plus `true` is a finding.
- XXE (benign): POST an XML body whose DOCTYPE declares only an *internal* entity, e.g. `<!DOCTYPE r [<!ENTITY a "x">]><r>&a;</r>`. A hardened parser rejects the DOCTYPE (4xx). If `x` is expanded, DTDs are processed and the parser config should be reviewed. No external or file entities are needed.
- TLS (staging/public): `testssl.sh https://staging.example`. The HTTP→HTTPS redirect applies to user-facing hosts.
- Cloud storage (own account): `aws s3api get-public-access-block --bucket <b>`, `aws s3api get-bucket-policy-status --bucket <b>`.
- Container: `docker inspect <img> --format '{{.Config.User}} {{.Config.Env}}'` (non-root user, no secrets). `docker history --no-trunc <img>` shows secrets baked into layers.

### Tools
- **Framework checks:** `python manage.py check --deploy --settings=<prod settings>` (Django). Spring Boot actuator config review. `dotnet user-secrets` / Key Vault for secrets.
- **Semgrep:** `semgrep scan --config p/owasp-top-ten --config p/security-audit --config p/secrets .`. Rules include `python.flask.security.audit.debug-enabled.debug-enabled`, `python.lang.security.use-defused-xml.use-defused-xml` and `java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing` (tagged A02:2025), plus `go.lang.security.audit.net.pprof.pprof-debug-exposure`. IaC packs: `p/dockerfile`, `p/terraform`, `p/kubernetes` (check the registry for current names).
- **CodeQL:** `js/insecure-helmet-configuration`, `js/cors-permissive-configuration`, `js/cors-misconfiguration-for-credentials`, `js/clear-text-cookie`, `js/samesite-none-cookie`, `js/stack-trace-exposure`, `js/xxe`; `py/flask-debug`, `py/insecure-cookie`, `py/xxe`, `py/stack-trace-exposure`; `java/spring-boot-exposed-actuators`, `java/spring-boot-exposed-actuators-config`, `java/xxe`, `java/insecure-cookie`, `java/sensitive-cookie-not-httponly`.
- **gosec:** G108 (pprof), G111 (`http.Dir("/")`), G112/G114 (server timeouts), G124 (cookie flags), G101 (hard-coded creds), G117 (secrets via marshaling).
- **Bandit:** B201 (flask debug), B104 (bind all interfaces), B313–B319 (XML calls; B320 removed), B405–B409/B411 (XML imports; B410 removed).
- **Secrets:** `gitleaks git .` and `gitleaks dir .` (`detect`/`protect` deprecated since v8.19). `trufflehog filesystem .`.
- **IaC/containers:** `trivy config .` or `trivy fs --scanners misconfig,secret .`. Pin a verified release: Trivy v0.69.4 binaries, v0.69.5/0.69.6 images and trivy-action/setup-trivy tags were compromised in March 2026 (GHSA-69fq-xp46-6x23). Also `checkov -d .` and `hadolint Dockerfile`. Cloud posture: `prowler aws`.
- **DAST (passive first):** `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:3000 -r zap.html` (the baseline scan does no attacks). `nuclei -u http://localhost:3000 -t http/misconfiguration/ -t http/exposures/ -exclude-tags dos,fuzz`. Headers: `npx @mdn/mdn-http-observatory <host>` (staging/public host). TLS: `testssl.sh`.

### Fix / remediation
- Use one hardened, versioned config per environment, deployed automatically. Prod must fail closed: refuse to boot if the secret key is missing or debug is on.
- Minimize the platform: remove sample apps, dev tooling, unused endpoints and verbs. Keep internal tooling on a separate internal listener.
- Set security headers centrally. Use a global last-resort error handler that returns a generic body and logs details server-side.
- Get secrets from a vault or managed identity. Never put them in images or client-prefixed env vars. Rotate anything that leaked.
- XML: disable DTDs entirely (the safest option) or use a hardened library (`defusedxml`).

Django (prod settings)
```python
DEBUG = False                                   # BAD: DEBUG = True / SECRET_KEY = "django-insecure-..."
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]    # KeyError = fail closed
ALLOWED_HOSTS = ["app.example.com"]
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000; SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_CONTENT_TYPE_NOSNIFF = True               # Django 6.0+: add ContentSecurityPolicyMiddleware + SECURE_CSP
CORS_ALLOWED_ORIGINS = ["https://app.example.com"]  # not CORS_ALLOW_ALL_ORIGINS=True with credentials
```
Express
```js
// BAD: app.use(cors({ origin: true, credentials: true })); res.status(500).send(err.stack)
app.use(helmet());                                            // CSP, HSTS, nosniff, removes X-Powered-By
app.use(cors({ origin: ['https://app.example.com'], credentials: true }));
app.use(session({ secret: process.env.SESSION_SECRET, name: '__Host-sid',
  cookie: { secure: true, httpOnly: true, sameSite: 'lax', path: '/' } }));
app.use((err, req, res, next) => { log.error(err); res.status(500).json({ error: 'Internal error', id: req.id }); });
```
Spring Boot (`application-prod.yml`) + XXE-safe parser
```yaml
management.endpoints.web.exposure.include: health     # BAD: "*"
server.error: { include-stacktrace: never, include-message: never }
server.servlet.session.cookie: { secure: true, http-only: true, same-site: lax }
spring.h2.console.enabled: false
```
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
dbf.setXIncludeAware(false); dbf.setExpandEntityReferences(false);
```
ASP.NET Core
```csharp
if (!app.Environment.IsDevelopment()) { app.UseExceptionHandler(); app.UseHsts(); }  // BAD: unconditional UseDeveloperExceptionPage()
app.UseHttpsRedirection();
builder.Services.AddCors(o => o.AddPolicy("web", p => p.WithOrigins("https://app.example.com").AllowCredentials()));
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
```

### Best-practice checklist
- [ ] Debug modes, dev error pages and profilers are off in production (ASVS 13.4.2). Debug binaries are not deployed.
- [ ] Generic error responses; a last-resort handler catches everything (16.5.1, 16.5.4).
- [ ] No `.git`/`.svn` or source-control metadata is deployed or reachable (13.4.1).
- [ ] Directory listing disabled (13.4.3). TRACE disabled (13.4.4). Only needed HTTP methods allowed (4.1.4).
- [ ] Internal docs, monitoring and actuator endpoints are not exposed unless intended (13.4.5). GraphQL introspection is off in prod unless intended (4.3.2).
- [ ] No detailed backend version info in headers or errors (13.4.6). Only allowlisted file extensions are served (13.4.7).
- [ ] No default credentials for any service (13.2.3). Least-privilege service accounts (13.2.2).
- [ ] Secrets come from a secrets manager with least-privilege access and rotation (13.3.1, 13.3.2, 13.3.4). None in images, repos or client env.
- [ ] Cookies: `Secure` + `__Host-`/`__Secure-` prefix (3.3.1, 3.3.3), `HttpOnly` for session cookies (3.3.4), purposeful `SameSite` (3.3.2).
- [ ] HSTS ≥1 year, with includeSubDomains at L2+ (3.4.1). TLS everywhere, no fallback (12.2.1).
- [ ] CORS origin is fixed or allowlisted; `*` only for non-sensitive data (3.4.2).
- [ ] CSP with `object-src 'none'`, `base-uri 'none'` and nonces/hashes or an allowlist (3.4.3). `frame-ancestors` (3.4.6). `nosniff` (3.4.4). Referrer-Policy (3.4.5). COOP on documents (3.4.8, L3).
- [ ] XML parsers disable DTDs and external entities (1.5.1).
- [ ] Containers run as non-root with minimal images. IaC is scanned in CI. No public buckets unless intended.
- [ ] Prod config is verified automatically on every deploy (check --deploy, header tests, IaC scan).

### Severity guidance
- **Critical:** Interactive debugger or console reachable (Werkzeug debugger, dev exception page with secrets, exposed Telescope/Ignition). Unauthenticated `/actuator/env` or `/actuator/heapdump`. Reachable `.env`/`.git` or public bucket containing live secrets or PII. Default admin credentials on an internet-facing admin panel or DB. XXE with external entity resolution on untrusted input (file read or SSRF). CORS reflecting any origin with credentials on an authenticated sensitive API.
- **High:** Stack traces or SQL errors exposing internals to unauthenticated users in prod. H2/DB console or pprof exposed publicly. Secrets in image layers or `NEXT_PUBLIC_*`. Session cookie without `Secure` on a site lacking HSTS. Entity-expansion DoS on an unauthenticated XML endpoint. Swagger or introspection exposing internal admin operations.
- **Medium:** Missing CSP or `frame-ancestors`/X-Frame-Options on an authenticated app. Missing HSTS. Session cookie missing `HttpOnly`. `SameSite=None` without need. Container running as root. TRACE enabled. Permissive CORS without credentials but on non-public data. Version banners for components with known CVEs.
- **Low:** `X-Powered-By`/`Server` banners. Missing Referrer-Policy, Permissions-Policy or COOP. Legacy `X-XSS-Protection: 1` (recommended value is `0`). Insecure settings confined to dev-only config that is verifiably not deployed (report as Info/Low).
- Adjust by exposure: internet-facing > internal. Credentials or secrets present in the leak → raise one level.

### Sources
- https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A02_2025-Security_Misconfiguration.md
- https://owasp.org/Top10/2025/0x00_2025-Introduction/
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A10_2025-Mishandling_of_Exceptional_Conditions.md
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A07_2025-Authentication_Failures.md
- https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- https://github.com/OWASP/ASVS ; ASVS 5.0 V13/V3/V1/V4/V12/V16: https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x22-V13-Configuration.md (and sibling chapter files)
- https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README
- https://docs.djangoproject.com/en/stable/howto/deployment/checklist/ ; https://docs.djangoproject.com/en/6.0/ref/csp/
- https://flask.palletsprojects.com/en/stable/config/ ; https://docs.python.org/3/library/xml.html
- https://www.starlette.io/middleware/ ; https://raw.githubusercontent.com/encode/starlette/master/starlette/middleware/cors.py
- https://raw.githubusercontent.com/adamchainz/django-cors-headers/main/src/corsheaders/middleware.py
- https://github.com/expressjs/cors ; https://github.com/expressjs/session
- https://docs.spring.io/spring-boot/reference/actuator/endpoints.html ; https://docs.spring.io/spring-framework/reference/web/webmvc-cors.html
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling ; https://learn.microsoft.com/en-us/aspnet/core/security/cors
- https://laravel.com/docs/csrf (Laravel 13.x)
- https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/python/flask/security/audit/debug-enabled.yaml
- https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/python/lang/security/use-defused-xml.yaml
- https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/java/lang/security/audit/xxe/documentbuilderfactory-disallow-doctype-decl-missing.yaml
- https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/go/lang/security/audit/net/pprof.yaml
- https://codeql.github.com/codeql-query-help/javascript/ ; https://codeql.github.com/codeql-query-help/python/ ; https://codeql.github.com/codeql-query-help/java/
- https://raw.githubusercontent.com/securego/gosec/master/RULES.md
- https://bandit.readthedocs.io/en/latest/plugins/index.html ; https://bandit.readthedocs.io/en/latest/blacklists/blacklist_imports.html
- https://github.com/gitleaks/gitleaks ; https://trivy.dev/latest/docs/scanner/misconfiguration/
- https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- https://www.zaproxy.org/docs/docker/baseline-scan/ ; https://docs.projectdiscovery.io/opensource/nuclei/running
- https://raw.githubusercontent.com/mdn/mdn-http-observatory/main/README.md
