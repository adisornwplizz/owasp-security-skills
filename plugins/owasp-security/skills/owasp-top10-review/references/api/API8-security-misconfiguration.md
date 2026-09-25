## API8:2023 – Security Misconfiguration
**Edition notes:** Was API7:2019 Security Misconfiguration; renumbered, same scope. On the web list it rose from A05:2021 to A02:2025. The official CWE list includes categories (CWE-2, CWE-16, CWE-388). MITRE marks CWE-16 as prohibited for mapping, so map findings to the specific CWEs below.
**Maps to Top 10:2025: A02** (Security Misconfiguration: CWE-16, CWE-489, CWE-942). Also A10 for verbose errors (CWE-209), A04 for cleartext (CWE-319), A06 for CWE-444 smuggling and CWE-525 browser cache, and A03 for unpatched components (the Log4Shell-style scenario).

### What it is (issue)
Insecure defaults, development settings that reach production, or missing hardening anywhere in the API stack (app, framework, server, proxy, container, cloud). The OWASP list: missing TLS, permissive or absent CORS, missing security and cache headers, unnecessary HTTP verbs and features, verbose errors with stack traces, unpatched systems, bad cloud permissions, and inconsistent parsing along the proxy chain. Official ratings: Exploitability Easy, Prevalence Widespread, Detectability Easy, Technical impact Severe.

### Root causes
- Framework dev defaults (debug mode, developer exception pages, API docs, consoles) promoted to prod through a shared config, a Dockerfile, or a missing `NODE_ENV`/`ASPNETCORE_ENVIRONMENT`.
- CORS configuration copy-pasted to "make it work" (reflecting any Origin with credentials).
- No hardened, repeatable baseline in IaC, and no automated drift or config scanning.
- TLS terminated at the edge with plaintext hops behind it; no `Cache-Control` on sensitive responses.
- Catch-all routing that accepts every HTTP verb and content type.
- Mismatched request parsing between proxy and app (smuggling), and components left unpatched.

### Key CWEs
- ★ CWE-942 Permissive Cross-domain Security Policy with Untrusted Domains, official (A02:2025)
- ★ CWE-209 Generation of Error Message Containing Sensitive Information, official (A10:2025)
- ★ CWE-489 Active Debug Code (A02:2025)
- ★ CWE-319 Cleartext Transmission of Sensitive Information, official (A04:2025)
- ★ CWE-444 Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling'), official (A06:2025)
- ★ CWE-525 Use of Web Browser Cache Containing Sensitive Information (official scenario #2; A06:2025)
- CWE-614 / CWE-1004 Sensitive cookie without `Secure` / `HttpOnly` (A02:2025)
- CWE-548 Directory listing
- Official categories that are not usable for mapping: CWE-2, CWE-16 Configuration, CWE-388

### How to detect — code review
- **Stack-agnostic:** check production config, env files, Dockerfiles (`CMD` running a dev server such as `npm run dev`, `flask run` or `manage.py runserver`), K8s and compose env, IaC (public buckets, `0.0.0.0/0` on admin ports), proxy config (NGINX/Envoy versions and HTTP/1 vs HTTP/2 downgrades), error handlers, CORS setup, header middleware, and route verb specificity.
- **Node:** `cors\(\{[^}]*origin:\s*(true|['"]\*['"])` together with `credentials:\s*true`; an origin callback that always returns `cb\(null,\s*true\)`; `res\.(json|send)\([^)]*(err|error)\.(stack|message)`; no `helmet\(`; no `disable\(['"]x-powered-by`; `NODE_ENV` not set to `production` (Express's default error handler prints stacks outside production). NestJS: `enableCors\(\s*\)` or `cors:\s*true` (wildcard). Next.js: `poweredByHeader` left on, `productionBrowserSourceMaps:\s*true`, and no security `headers()` in `next.config`.
- **Python:** Django `DEBUG\s*=\s*True`, `ALLOWED_HOSTS\s*=\s*\[\s*['"]\*`, `CORS_(ALLOW_ALL_ORIGINS|ORIGIN_ALLOW_ALL)\s*=\s*True`, and missing `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`. FastAPI/Starlette: `allow_origins=\[["']\*["']\]` plus `allow_credentials=True`; Starlette then echoes any `Origin` back, which I confirmed in the source. Flask: `\.run\([^)]*debug=True` or `FLASK_DEBUG=1`; the Werkzeug debugger allows code execution.
- **Java/Spring:** `@CrossOrigin` with no `origins` (defaults to all), `allowedOriginPatterns\("\*"\)` with `allowCredentials\(true\)`, `server\.error\.include-(stacktrace|message)=always`, `management\.endpoints\.web\.exposure\.include=\*`, `spring\.h2\.console\.enabled=true`, and `@RequestMapping` without `method` (matches every verb).
- **Go:** `Set\("Access-Control-Allow-Origin",\s*r\.Header\.Get\("Origin"\)\)`; rs/cors `AllowOriginFunc` that always returns true, combined with `AllowCredentials: true`; gin `cors\.Default\(\)` (all origins); `_ "net/http/pprof"` or `"expvar"` with `ListenAndServe\([^,]+,\s*nil\)` (DefaultServeMux); `http\.Error\(w,\s*err\.Error\(\)`.
- **Laravel:** `APP_DEBUG=true` in prod env or compose. In `config/cors.php`, `'allowed_origins' => ['*']` plus `'supports_credentials' => true`; fruitcake/php-cors then reflects any Origin, which I confirmed in the source. Also `phpinfo\(` and `Route::any\(`.
- **.NET:** `UseDeveloperExceptionPage\(` outside `IsDevelopment()`, `ASPNETCORE_ENVIRONMENT=Development` in the image or manifests, `SetIsOriginAllowed\([^)]*=>\s*true\)` with `AllowCredentials\(\)`, no `UseHsts\(`/`UseHttpsRedirection\(` on browser-facing apps, and actions with no `[Http*]` attribute (all verbs).
- **GraphQL:** introspection or GraphiQL/Playground enabled in prod; Apollo `includeStacktraceInErrorResponses: true`, `hideSchemaDetailsFromClientErrors` not set (leaks "Did you mean" suggestions), `csrfPrevention: false`; mutations accepted over GET; Spring `spring.graphql.graphiql.enabled=true`.
- **False positives:** `ACAO: *` **without** credentials on public, unauthenticated read-only data. Debug flags that exist only in dev or test settings (confirm which file prod loads). Plain HTTP inside a mesh with mTLS sidecars. HSTS matters less for pure machine-to-machine APIs, though TLS is still required.

### How to detect — runtime (safe, own app only)
- **Headers:** `curl -sI https://staging.example.com/api/me -H "Authorization: Bearer $T"`. Expect `Strict-Transport-Security`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store` on sensitive data, and no version-bearing `Server`/`X-Powered-By`.
- **CORS:** `curl -sI -H "Origin: https://evil.example" .../api/me`, then again with `-H "Origin: null"`. Expect no ACAO echoing those values, and never together with `Access-Control-Allow-Credentials: true`.
- **Verbs and content types:** `curl -X TRACE`, `-X PUT` on read-only routes, and `-H 'Content-Type: text/xml'` on JSON routes. Expect 405 or 415.
- **Errors:** POST a malformed body (`-d '{"a":'`). Expect a generic 400 with no stack, SQL or paths.
- **Debug and consoles:** `/actuator/env`, `/actuator/heapdump`, `/debug/pprof/`, `/_ignition/health-check`, `/h2-console`, `/.git/HEAD`, `/.env` should all return 404 or 401.
- **TLS:** `testssl.sh https://staging.example.com`. Expect only TLS 1.2 and 1.3. API hosts should not transparently redirect HTTP to HTTPS (ASVS 4.1.2).
- **GraphQL:** `curl -s -X POST -H 'Content-Type: application/json' -d '{"query":"{__schema{types{name}}}"}' .../graphql` should return an error in prod. A misspelled field should produce no "Did you mean".

### Tools
- Django `python manage.py check --deploy`; `testssl.sh` or `sslyze`.
- ZAP baseline: `docker run -t zaproxy/zap-stable zap-baseline.py -t https://staging.example.com`.
- `nuclei -u https://staging.example.com -tags misconfig,exposure,debug,springboot,graphql`.
- IaC: `trivy config .` and `checkov -d .`.
- Semgrep: `javascript/express/security/cors-misconfiguration.yaml`, `typescript/nestjs/security/audit/nestjs-header-cors-any.yaml`, `python/fastapi/security/wildcard-cors.yaml`, `python/flask/security/audit/debug-enabled.yaml`, `java/spring/security/audit/spring-actuator-fully-enabled{,-yaml}.yaml`, `go/lang/security/audit/net/pprof.yaml`, `php/lang/security/phpinfo-use.yaml`. `p/owasp-top-ten` and `p/security-audit` for broad coverage.
- CodeQL: `js/cors-permissive-configuration`, `js/stack-trace-exposure`, `py/stack-trace-exposure`, `java/stack-trace-exposure`, `py/flask-debug`, `java/spring-boot-exposed-actuators`. Bandit `B201` (flask debug); gosec `G108` (pprof exposed).
- Spectral OWASP: `owasp:api8:2023-define-cors-origin`, `-no-scheme-http`, `-no-server-http`, `-define-error-responses-500`, `-define-error-validation`.

### Fix / remediation
```js
// Express — BAD
app.use(cors({ origin: true, credentials: true }));                 // reflects any Origin
app.use((err, req, res, next) => res.status(500).json({ error: err.message, stack: err.stack }));
// GOOD
app.disable("x-powered-by"); app.use(helmet());
app.use(cors({ origin: ["https://app.example.com"], credentials: true, methods: ["GET", "POST"] }));
app.use((err, req, res, next) => { log.error({ err, id: req.id }); res.status(500).json({ error: "internal_error", id: req.id }); });
```
```python
# FastAPI — BAD: allow_origins=["*"], allow_credentials=True  (Starlette echoes any Origin)
app = FastAPI(debug=False, docs_url=None, redoc_url=None, openapi_url=None)   # prod
app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"], allow_credentials=True,
                   allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
```
```yaml
# Spring Boot application-prod.yml (first four are Boot defaults, so flag any override; introspection must be set explicitly)
server.error: { include-stacktrace: never, include-message: never }
management.endpoints.web.exposure.include: health
spring.h2.console.enabled: false
spring.graphql.schema.introspection.enabled: false
```
Also: TLS 1.2 or 1.3 on every hop, internal ones included. Set `Cache-Control: no-store` on authenticated responses. Allow only the verbs and content types each route needs. For GraphQL: `introspection: false`, `hideSchemaDetailsFromClientErrors: true`, keep `csrfPrevention` on; in graphql-js servers use `NoSchemaIntrospectionCustomRule`. Keep proxy and app servers patched and consistent (HTTP/2 end-to-end, or normalize at the edge).

### Best-practice checklist
- [ ] HSTS ≥ 1 year (ASVS 3.4.1), and CORS origin fixed or allowlisted (ASVS 3.4.2)
- [ ] `nosniff` (ASVS 3.4.4), and Content-Type with charset set on every response (ASVS 4.1.1)
- [ ] Only supported HTTP methods allowed (ASVS 4.1.4), and TRACE disabled (ASVS 13.4.4)
- [ ] Consistent HTTP message framing across the chain (ASVS 4.2.1)
- [ ] TLS 1.2/1.3 only (ASVS 12.1.1); TLS on all external and internal connections (ASVS 12.2.1, 12.3.1, 12.3.3)
- [ ] Debug modes off (ASVS 13.4.2); no `.git` (ASVS 13.4.1); no directory listing (ASVS 13.4.3); no backend version info (ASVS 13.4.6)
- [ ] Generic error messages (ASVS 16.5.1); `Cache-Control: no-store` on sensitive data (ASVS 14.3.2)
- [ ] GraphQL introspection off in prod unless the API is public (ASVS 4.3.2)
- [ ] No extraneous or dev functionality in prod (ASVS 15.2.3)
- [ ] Hardened baseline in IaC, scanned in CI (trivy/checkov), with drift detection

### Severity guidance
- **Critical:** a debug or console surface that allows code execution or leaks secrets (Werkzeug debugger, H2 console, actuator `env`/`heapdump`, Laravel debug page exposing env); public storage holding PII; a known-exploitable insecure default in an unpatched component.
- **High:** CORS that reflects arbitrary Origins with credentials on an authenticated API; credentials or PII sent over plaintext; errors leaking secrets or connection strings; a proxy chain prone to smuggling.
- **Medium:** stack traces or version disclosure without secrets; no `no-store` on sensitive responses; introspection on a private GraphQL API; TRACE enabled; TLS 1.0 or 1.1 accepted.
- **Low:** missing defense-in-depth headers on JSON APIs (Referrer-Policy, COOP); `X-Powered-By`; extra verbs that do nothing harmful.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/
- https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/ and A10/A04/A06 2025 pages (github.com/OWASP/Top10 2025/docs/en)
- https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (V3, V4, V12, V13, V14, V16)
- https://cwe.mitre.org/data/definitions/16.html ; https://cwe.mitre.org/data/definitions/942.html
- https://github.com/encode/starlette/blob/master/starlette/middleware/cors.py ; https://github.com/fruitcake/php-cors/blob/master/src/CorsService.php
- https://www.apollographql.com/docs/apollo-server/api/apollo-server ; https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://www.zaproxy.org/docs/docker/about/ ; https://github.com/projectdiscovery/nuclei-templates (tags checked)
- https://github.com/stoplightio/spectral-owasp-ruleset (src/ruleset.ts rule names)

---
