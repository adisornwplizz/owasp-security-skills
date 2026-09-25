## API9:2023 – Improper Inventory Management
**Edition notes:** Renamed from API9:2019 "Improper Assets Management". The 2023 edition adds "data flow blindspots" (sensitive data shared with third parties) alongside documentation and host-inventory blindspots.
**Maps to Top 10:2025: no direct equivalent.** Closest are A02 (exposed docs and debug endpoints, CWE-489), A06 (CWE-1125 Excessive Attack Surface) and A03 (old or unmaintained versions and components, SBOM).

### What it is (issue)
The team doesn't know which API hosts, versions and endpoints exist, where they run, who can reach them, or which sensitive data flows to third parties. As a result, old versions (`/v1`), beta and staging hosts, debug and test routes, undocumented ("shadow") and deprecated-but-running ("zombie") endpoints stay exposed with weaker controls, often wired to production data. Official ratings: Exploitability Easy, Prevalence Widespread, Detectability Average, Technical impact Moderate.

### Root causes
- No single source of truth: the spec is hand-written and drifts from the code, and nobody diffs them.
- Versioning without a retirement plan; security fixes land only in the newest version.
- Controls like rate limiting live in one gateway or deployment, so other hosts skip them (official scenario #1: a beta host without rate limiting enabled a brute-force of reset tokens).
- Environment sprawl (preview or per-branch deploys, K8s services, forgotten DNS records), and production data copied into non-prod.
- Third-party SDKs and integrations (analytics, error tracking, CRM, LLM) added without a data-flow review or least-scope sharing (official scenario #2).

### Key CWEs
- CWE-1059 Insufficient Technical Documentation (the official mapping; formerly "Incomplete Documentation"). MITRE marks it **PROHIBITED** for vulnerability mapping, so use the specific CWEs below.
- ★ CWE-1125 Excessive Attack Surface (A06:2025)
- ★ CWE-489 Active Debug Code (A02:2025)
- ★ CWE-215 Insertion of Sensitive Information Into Debugging Code (A10:2025)
- ★ CWE-912 Hidden Functionality
- ★ CWE-1104 Use of Unmaintained Third Party Components (A03:2025)
- ★ CWE-359 Exposure of Private Personal Information to an Unauthorized Actor (third-party data flows)
- CWE-200 Exposure of Sensitive Information to an Unauthorized Actor (A01:2025)

### How to detect — code review
- **Stack-agnostic:** generate the route inventory from code and diff it against the committed OpenAPI or GraphQL schema. Grep for coexisting version prefixes (`/v1/` and `/v2/`) and `/(beta|internal|debug|test|dev|old|legacy|tmp|admin|_)`. Look for endpoints excluded from docs, and for docs, debug or console routes registered without an environment guard. In IaC, check API Gateway stages, ingress hosts (`beta\.|staging\.|dev\.`), DNS records, public preview deploys, and DB connection strings shared across environments. For outbound SDKs, record what data leaves and whether PII is sent.
- **Node:** `app\.use\(['"]/(api-docs|docs|swagger)` without an env check. NestJS: `SwaggerModule\.setup\(` unguarded; `@ApiExcludeEndpoint\(|@ApiExcludeController\(` mark undocumented endpoints. Next.js: every `app/**/route.(ts|js)`, `pages/api/**` file and `'use server'` export is a live endpoint, so look for leftover test routes.
- **Python:** FastAPI `FastAPI\(` in prod without `docs_url=None, redoc_url=None, openapi_url=None`; `include_in_schema=False` marks hidden routes. Django: `path\(['"](debug|test|internal)`, `debug_toolbar` in prod `INSTALLED_APPS`, a public `SpectacularSwaggerView`. Flask-RESTX `Api(` serves Swagger UI by default (set `doc=False`). Sentry `send_default_pii=True` is a data-flow item.
- **Java/Spring:** `springdoc.api-docs.enabled` and `springdoc.swagger-ui.enabled` not set to false in the prod profile; `@Hidden` endpoints; test controllers without `@Profile("dev")`.
- **Go:** `_ "net/http/pprof"` registers `/debug/pprof/` and `"expvar"` registers `/debug/vars` on the DefaultServeMux; also `Handle(Func)?\(["']/(debug|internal|v1)`. Inventory with `chi.Walk` or gin `router.Routes()`.
- **Laravel:** `php artisan route:list --json` gives the inventory. Look for `Route::prefix\('v1'\)` alongside v2, Telescope and Horizon gates (`viewTelescope`, `viewHorizon`), and l5-swagger `/api/documentation` left public.
- **.NET:** `UseSwagger\(|UseSwaggerUI\(|MapOpenApi\(` outside `IsDevelopment()`; `[ApiExplorerSettings(IgnoreApi = true)]` marks hidden endpoints; `[ApiVersion("1.0", Deprecated = true)]` still mapped with no sunset.
- **GraphQL:** multiple endpoints (`/graphql`, `/v1/graphql`, `/graphiql`, `/altair`); `@deprecated` fields never removed; no schema registry or change checks.
- **False positives:** public docs for a public API are fine (ASVS 13.4.5 says "unless explicitly intended"). Multiple live versions are fine if every one gets the same controls and has a sunset date. Undocumented internal endpoints are acceptable when network-isolated **and** authenticated.

### How to detect — runtime (safe, own app only)
- **Probe docs and debug paths on every environment:** `/openapi.json /swagger-ui/ /v3/api-docs /api-docs /docs /redoc /graphql /graphiql /actuator /debug/pprof/ /telescope /horizon`. Prod should return 404 or 401 unless intended.
- **Enumerate versions:** `for v in v0 v1 v2 v3 beta internal; do curl -s -o /dev/null -w "$v %{http_code}\n" -H "Authorization: Bearer $T" https://staging.example.com/api/$v/users/me; done`.
- **Parity:** run the same authZ, rate-limit and input-validation tests against every host and version (`beta.api`, staging, `/v1`). The results must match current prod.
- **Deprecation:** deprecated versions should send `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) headers, and return 410 after sunset.
- **Drift:** diff the served spec against the committed one. Check that non-prod environments hold no real customer data.

### Tools
- Spectral OWASP: `owasp:api9:2023-inventory-access` (declare audience via `servers[].x-internal`) and `owasp:api9:2023-inventory-environment`.
- `oasdiff breaking base.yaml new.yaml` for spec diffs in CI. Framework route dumps (listed above) diffed against the spec.
- `nuclei -u <staging> -tags swagger,graphql,springboot,exposure,debug`.
- ZAP API scan: `docker run -v $(pwd):/zap/wrk/:rw -t zaproxy/zap-stable zap-api-scan.py -t openapi.yaml -f openapi` (also `-f graphql`).
- Kiterunner (`kr scan <own-host> -w routes-large.kite`) to find undocumented routes on your own hosts.
- SBOM and outdated components per deployed version: `syft`/`cdxgen` plus `osv-scanner`.

### Fix / remediation
- Generate the spec from code in CI (or code from the spec) and fail the build on drift. Publish docs only to authorized audiences. Keep an inventory of each host's env, audience, version, owner, data classification and sunset date, plus a third-party data-flow register (what data, why, approval).
- Apply the same auth, rate-limit and WAF middleware to all versions and hosts. Put routing deny-by-default at the gateway. Retire old versions (Deprecation and Sunset headers, then 410), or backport security fixes after a risk analysis. Keep non-prod off production data.
```python
# FastAPI — BAD: FastAPI()  -> /docs, /redoc, /openapi.json public in prod
docs = {} if settings.ENV == "dev" else {"docs_url": None, "redoc_url": None, "openapi_url": None}
app = FastAPI(**docs)
```
```csharp
// ASP.NET Core — BAD: app.MapOpenApi(); app.UseSwaggerUI();   (unconditional)
if (app.Environment.IsDevelopment()) { app.MapOpenApi(); app.UseSwaggerUI(); }
```
```go
// Go — BAD: import _ "net/http/pprof" + http.ListenAndServe(":8080", nil)
mux := http.NewServeMux()                          // public API: explicit mux, no pprof
go http.ListenAndServe("127.0.0.1:6060", nil)      // pprof only on loopback / internal port
http.ListenAndServe(":8080", mux)
```

### Best-practice checklist
- [ ] All communication needs, including external services and user-supplied destinations, are documented (ASVS 13.1.1)
- [ ] Docs and monitoring endpoints are not exposed unless intended (ASVS 13.4.5), and debug modes are off (ASVS 13.4.2)
- [ ] No extraneous test, sample or dev functionality in prod (ASVS 15.2.3); GraphQL introspection is off unless the API is public (ASVS 4.3.2)
- [ ] An SBOM covers every deployed version (ASVS 15.1.2), and components stay within remediation time frames (ASVS 15.2.1)
- [ ] Host inventory covers env, audience, version, owner and sunset date; the spec is generated in CI and checked for drift
- [ ] Identical controls on every version and host; deprecated versions are retired on schedule (Deprecation/Sunset headers, then 410)
- [ ] A third-party data-flow register exists with business justification and least-scope sharing
- [ ] No production data in non-prod, or else non-prod gets prod-level controls

### Severity guidance
- **Critical:** a forgotten version or beta host missing authN, authZ or rate limiting on sensitive flows (reset-token brute force) while connected to prod data; exposed debug endpoints that leak secrets (heapdump, env).
- **High:** a still-running deprecated version with a vulnerability fixed only in the new version; a third party receiving sensitive data without justification, or through over-broad scopes.
- **Medium:** public internal docs or introspection revealing hidden admin endpoints; pprof or expvar exposed (information leak, DoS).
- **Low:** no deprecation or sunset plan or headers; spec drift with no control difference.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/ (and raw .md)
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/ ; https://cwe.mitre.org/data/definitions/1059.html
- https://top10.owasp.org/2025/ (A02, A03, A06 pages via github.com/OWASP/Top10)
- https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (V4, V13, V15)
- https://github.com/stoplightio/spectral-owasp-ruleset ; https://www.zaproxy.org/docs/docker/api-scan/
- https://www.rfc-editor.org/info/rfc9745/ (Deprecation header) ; RFC 8594 (Sunset)

---
