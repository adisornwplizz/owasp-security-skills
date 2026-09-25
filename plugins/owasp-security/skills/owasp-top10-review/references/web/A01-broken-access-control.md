## A01:2025 – Broken Access Control
**Edition notes:** Still #1 (was #1 in 2021). SSRF (A10:2021, CWE-918) was merged in ("Server-Side Request Forgery (SSRF) has been rolled into this category"). The 2025 category maps 40 CWEs (2021: 34). Official stats: max incidence 20.15%, avg incidence 3.74%, avg coverage 42.93%, 1,839,701 occurrences, 32,654 CVEs; "100% of the applications tested were found to have some form of broken access control." The page calls out CWE-200, CWE-201, CWE-918 and CWE-352 as notable. Reference standard is now ASVS 5.0.0 (May 2025) **V8 Authorization**. API Top 10:2023 overlap: API1 BOLA (=IDOR), API3 BOPLA (field-level/mass assignment), API5 BFLA (function-level), API7 SSRF. Boundary notes: CORS *policy config* (CWE-942) is mapped to A02; Origin validation (CWE-346), session expiry (CWE-613) and session fixation (CWE-384) are mapped to A07:2025, even though the A01 page lists CORS abuse and logout/JWT invalidation. Directory listing (CWE-548) is mapped here, not A02.

### What it is (issue)
Access control enforces policy so users "cannot act outside of their intended permissions." It fails when the server does not check, on every request, that *this* subject may perform *this* action on *this* object/field (IDOR/BOLA, missing function-level checks, privilege escalation, forced browsing, JWT/cookie tampering). It also covers the server being tricked into using its own authority on the attacker's behalf: CSRF (the browser's ambient cookies), SSRF (the server's network position), path traversal (the server's filesystem rights) and open redirects.

### Root causes
- Authorization is opt-in per handler instead of deny-by-default (no global guard or fallback policy), so new routes ship unprotected.
- Treating authentication as authorization: "logged in" is taken to mean "allowed". Checks look at the role but never at who owns the record or which tenant it belongs to.
- Data access by client-supplied key (`findById(req.params.id)`) with no owner or tenant scoping. Random UUIDs make IDs harder to guess but are not an access check.
- Trusting client-controlled state: role or `isAdmin` in the body or query, hidden fields, unverified JWT claims, UI-only hiding.
- Checks only at the edge (gateway, middleware or proxy) while there are other ways to reach the handler: Server Actions, alternate HTTP methods, API versions, GraphQL resolvers, WebSockets, jobs. Next.js CVE-2025-29927 is the canonical example.
- Authorization logic duplicated across controllers instead of centralized (policy/DAL), so it drifts.
- Stateless tokens with no revocation, long lifetimes, logout that only deletes the client cookie.
- Cookie auth combined with state-changing GET or no CSRF defense. SameSite is treated as the whole CSRF defense.
- Outbound fetches or file paths built from user input with no allowlist (confused deputy).
- Request-to-model auto-binding exposes privileged fields (BOPLA / mass assignment).
- Test suites only cover the happy path. There are no negative authz tests (user A fetches B's object).

### Key CWEs
All 40 mapped: CWE-22, 23, 36, 59, 61, 65, 200, 201, 219, 276, 281, 282, 283, 284, 285, 352, 359, 377, 379, 402, 424, 425, 441, 497, 538, 540, 548, 552, 566, 601, 615, 639, 668, 732, 749, 862, 863, 918, 922, 1275.
Most relevant for web/API devs (★):
- ★ CWE-862 Missing Authorization / ★ CWE-863 Incorrect Authorization
- ★ CWE-639 Authorization Bypass Through User-Controlled Key (IDOR/BOLA); CWE-566 (same via SQL primary key)
- ★ CWE-352 Cross-Site Request Forgery (CSRF); CWE-1275 Sensitive Cookie with Improper SameSite Attribute
- ★ CWE-918 Server-Side Request Forgery (SSRF); CWE-441 Unintended Proxy ('Confused Deputy')
- ★ CWE-22 Path Traversal (+ CWE-23 relative, CWE-36 absolute, CWE-59/61 link following)
- ★ CWE-425 Direct Request ('Forced Browsing'); CWE-284/285 Improper Access Control / Authorization
- ★ CWE-601 Open Redirect
- ★ CWE-200 Exposure of Sensitive Information to an Unauthorized Actor; CWE-201; CWE-359 (PII); CWE-548 Directory Listing; CWE-552 Files Accessible to External Parties; CWE-538/540/615 secrets in public files, source or comments

### How to detect — code review
**Stack-agnostic signals**
- Build a route inventory (router files, decorators/attributes, OpenAPI spec, `app/**/route.ts`, GraphQL schema, WS handlers). For each route × method, record the required role, the ownership or tenant check, and where the check runs. Any row with no explicit decision is a finding.
- Look for a global default first: global guard, fallback policy, `DEFAULT_PERMISSION_CLASSES`, Spring `anyRequest().authenticated()`. If there is none, every handler needs its own check.
- ORM/SQL lookups keyed by request data with no `owner_id`/`tenant_id` predicate; list endpoints returning `.all()`; bulk update/delete by ID list.
- Role or permission read from request body, query, header or unsigned cookie; `if (user.role === req.body.role)`; client-side `if (isAdmin)` as the only gate.
- JWT: `decode` without verify, algorithm not pinned, `none` accepted, `jku`/`x5u`/`kid` used to fetch keys from token-supplied URLs, `exp` of days or weeks, no denylist on logout.
- CSRF: framework protection disabled or exempted, state-changing `GET`, cookie auth with no token/Origin/Sec-Fetch-Site check, `SameSite=None`.
- Outbound HTTP (fetch/axios/requests/httpx/http.Get/RestTemplate/WebClient/HttpClient/Guzzle) whose URL, host or path comes from request data. Typical features: webhooks, "import from URL", avatar by URL, PDF/HTML renderers, OIDC discovery, link previews. Redirect-following enabled.
- File APIs (`sendFile`, `open`, `File`, `Path.Combine`, `filepath.Join`, `Storage::get`) with user-supplied names; archive extraction (zip slip).
- `redirect(...)` with a user-supplied `next`, `returnUrl` or `redirect_uri`.
- Uploads or exports served from a public web root or public bucket with no per-object check; long-lived presigned URLs.
- Infra: gateway/ingress rules that expose admin paths; `.git`, backups or `.map` files in web root.

**Node (Express / NestJS / Next.js)**
- Unscoped lookup: `rg -n "(findById|findByPk|findUnique|findOne|findFirst)\([^)]*req\.(params|query|body)"`
- Role from client: `rg -n "req\.(body|query|headers)\.(role|isAdmin|is_admin|userId|ownerId)"`
- JWT: `rg -n "jwt\.decode\(|ignoreExpiration:\s*true|algorithms:\s*\[[^\]]*['\"]none"`, plus `jwt.verify(` calls without `algorithms:`.
- Path traversal: `rg -n "(sendFile|download|createReadStream|readFile)\([^)]*req\.|path\.(join|resolve)\([^)]*req\."`
- SSRF: `rg -n "(fetch|axios(\.\w+)?|got|needle|http\.get|https\.get)\(\s*[^'\"\`)]*req\.(query|body|params)"`
- Open redirect: `rg -n "res\.redirect\([^)]*req\.(query|body|params)"`
- NestJS: check for an `APP_GUARD` provider (`rg -n "APP_GUARD"`) and review every `@Public()`/`@SkipAuth()`-style decorator. Controllers without `@UseGuards` are open if no global guard exists.
- Next.js: auth only in `middleware.ts`/`proxy.ts` (Next 16 renamed middleware to proxy). Every `'use server'` file and `app/**/route.ts` handler must call the session/DAL check itself (`rg -l "'use server'"` then grep for `verifySession|auth\(|getServerSession`). Check that `next` is patched for CVE-2025-29927 (≥12.3.5 / 13.5.9 / 14.2.25 / 15.2.3).
- CSRF: `csurf` is deprecated. Look for no CSRF middleware at all while cookie sessions are in use.

**Python (Django / DRF / FastAPI / Flask)**
- `rg -n "@csrf_exempt|csrf_exempt\("`
- DRF default is `AllowAny` when `DEFAULT_PERMISSION_CLASSES` is unset: `rg -n "DEFAULT_PERMISSION_CLASSES|permission_classes\s*=\s*\[?\s*AllowAny"`
- Unscoped querysets: `rg -n "queryset\s*=\s*\w+\.objects\.all\(\)|objects\.get\((pk|id)=\w+\)"`. Object permissions are not applied to list views, and `has_object_permission` is not applied when `get_object()` is overridden without `check_object_permissions`.
- FastAPI routes with no auth dependency: `rg -n "@(app|router)\.(get|post|put|patch|delete)\("` and check for `Depends(`/`Security(`/`dependencies=` on the route or router.
- PyJWT: `rg -n "verify_signature.{0,3}:\s*False"`. Also check that each `jwt.decode(` passes `algorithms=[...]`.
- Path: `rg -n "send_file\([^)]*request\.|open\([^)]*request\.(args|form|json|GET|POST)"` (prefer `send_from_directory`).
- SSRF: `rg -n "(requests|httpx)\.(get|post|request|stream)\([^)]*request\.|urlopen\("`
- Redirect: `rg -n "redirect\(\s*request\.(args|GET|POST)"`. Django should use `url_has_allowed_host_and_scheme`.

**Java (Spring Boot / Spring Security)**
- `rg -n "anyRequest\(\)\.permitAll|permitAll\(\)"`. Review each `requestMatchers(...)` ordering.
- CSRF off: `rg -n "csrf\(\s*\w+\s*->\s*\w+\.disable\(\)\)|csrf\(\)\.disable\(\)|csrf\(AbstractHttpConfigurer::disable\)"`. This is fine only for pure bearer-token APIs.
- Method security: is `@EnableMethodSecurity` present? Do handlers taking `@PathVariable` IDs call `repository.findById(id)` with no owner check or `@PreAuthorize`/`@PostAuthorize`?
- Path: `rg -n "new File\([^)]*(getParameter|Param)|Paths\.get\([^)]*(getParameter|Param)"`
- SSRF: `rg -n "(RestTemplate|RestClient|WebClient|HttpClient|new URL)\b"` then trace the URL argument back to request input.
- Redirect: `rg -n "\"redirect:\"\s*\+"`

**Go**
- IDs from `r.PathValue("id")`, `chi.URLParam(r,"id")`, `c.Param("id")` (gin/echo) passed to `GetByID(ctx, id)` without the user or tenant.
- Path: `rg -n "filepath\.Join\([^)]*(r\.URL|PathValue|FormValue|c\.Param|c\.Query)|http\.ServeFile\(w,\s*r,\s*[a-z]"`
- SSRF: `rg -n "http\.(Get|Post|Head)\(\s*[a-zA-Z_]|http\.NewRequest(WithContext)?\([^\"]*,\s*[a-zA-Z_]"`
- JWT: `rg -n "ParseUnverified|jwt\.Parse\("`. Check that the key func verifies `t.Method` or that `jwt.WithValidMethods(...)` is passed (golang-jwt v5).
- CSRF: no `http.NewCrossOriginProtection` (Go 1.25+) or equivalent on cookie-auth mutating routes.
- Redirect: `rg -n "http\.Redirect\(w,\s*r,\s*r\."`

**PHP (Laravel)**
- `rg -n "::(find|findOrFail)\(\s*\$(id|request)"` with no `Gate::authorize`, `$this->authorize`, `->can(`, `#[Authorize]` or relationship scoping (`$request->user()->orders()->findOrFail($id)`).
- Routes outside `auth`/`can:` middleware groups: review `routes/*.php` for `->middleware('auth` coverage.
- CSRF exclusions (version-dependent): `rg -n "protected \$except|validateCsrfTokens\(except:|preventRequestForgery\(except:"`
- Mass assignment (BOPLA): `rg -n "\$guarded\s*=\s*\[\s*\]|->(update|create|fill)\(\$request->all\(\)\)"`
- Path/SSRF: `rg -n "Storage::(get|download)\(\$request|file_get_contents\(\$|Http::(get|post)\(\$request|CURLOPT_URL,\s*\$"`
- Redirect: `rg -n "redirect\(\)->away\(\$request|redirect\(\$request->"`

**.NET (ASP.NET Core)**
- Deny-by-default present? `rg -n "FallbackPolicy|SetFallbackPolicy"`. Inventory `[AllowAnonymous]`.
- Object checks: `rg -n "\.(FindAsync|Find)\(\s*id\s*\)|FirstOrDefaultAsync\(\s*\w+\s*=>\s*\w+\.Id\s*==\s*id\s*\)"` with no `IAuthorizationService.AuthorizeAsync(User, resource, ...)` or user predicate.
- CSRF: `rg -n "\[IgnoreAntiforgeryToken\]|\.DisableAntiforgery\(\)"`
- Path: `rg -n "Path\.Combine\([^)]*(Request\.|\[From(Query|Route|Body|Form)\])"`
- Redirect: `rg -n "Redirect\(\s*returnUrl\s*\)"`. Should be `LocalRedirect` / `Url.IsLocalUrl`.

**False-positive notes**
- Public-by-design routes (health, login, public catalog) are fine. Confirm the intent against the spec or route inventory.
- Unscoped lookups can be safe when scoping happens elsewhere: Postgres row-level security, EF Core `HasQueryFilter`, Hibernate filters, tenant-scoped managers/repositories, or a policy check right after the fetch. Verify that it really runs on this path.
- CSRF exemptions are fine for webhooks verified by HMAC signature and for APIs that authenticate only via `Authorization: Bearer` (no cookies).
- Outbound URLs from server config or env are not SSRF. Joins with a constant name or a server-generated UUID are not traversal.
- Reading a JWT header (e.g. `kid`) before verification is normal if the token is then fully verified.

### How to detect — runtime (safe, own app only)
Create two users in the same role (A, B), one admin, and, if multi-tenant, a user in tenant 2. Use localhost or staging only.
- IDOR/BOLA: `curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN_A" http://localhost:3000/api/orders/$ORDER_ID_OF_B`. Expect 403/404. Repeat for PUT/PATCH/DELETE, nested routes (`/users/$B/orders`), exports and GraphQL `node(id:)`.
- BFLA/forced browsing: call every admin route with user A's token and with no token. Expect 403/401. Try method switching (`-X DELETE`, `-X PUT`) and alternate paths (`/api/v1/` vs `/api/v2/`, trailing slash, case).
- BOPLA: `PATCH /api/users/me -d '{"role":"admin"}'` as A, then GET: the role must be unchanged. Check that responses do not include fields A should not see.
- Unauthenticated sweep: iterate over OpenAPI paths without credentials. Everything not marked public should return 401.
- Session/JWT: log out, then replay the old cookie or token (expect 401). Edit a JWT payload claim without re-signing, or set header `alg` to `none` (expect 401). Check the `exp` lifetime.
- CSRF (cookie-auth apps): replay a state-changing POST with a valid session cookie but no CSRF token, with `Origin: https://evil.example`, or with `Sec-Fetch-Site: cross-site`. Expect 403.
- CORS: `curl -si -H 'Origin: https://evil.example' -H "Cookie: $SESSION" http://localhost:3000/api/me | grep -i '^access-control'`. Reflected origin together with `Access-Control-Allow-Credentials: true` is a finding. Also try `Origin: null`.
- Path traversal: request your own app's harmless file through the download param, e.g. `?file=../package.json` and `..%2fpackage.json`. Expect 400/404, never the file.
- SSRF: start a local canary (`python3 -m http.server 8081`) and submit `http://127.0.0.1:8081/` and `http://[::1]:8081/`. Then point it at a canary that returns `302` to `http://127.0.0.1:8081/`. The app should reject loopback/private/link-local targets and must not follow redirects. Watch the canary log.
- Open redirect: `GET /login?next=https://example.org` should not send a `Location` to an off-site host.
- Forced browsing of files: `/.git/HEAD`, `/.env`, `/backup.zip`, `/*.map`, `/uploads/`. Expect 404 and no directory index.

### Tools
- **Semgrep:** `semgrep scan --config p/owasp-top-ten --config p/security-audit .`. Relevant rules include `python.django.security.audit.csrf-exempt.no-csrf-exempt` and `java.spring.security.audit.spring-csrf-disabled.spring-csrf-disabled` (both tagged A01:2025). Framework packs: `p/django`, `p/flask`, `p/java`, `p/php`, `p/csharp`, `p/golang`, `p/javascript`, `p/typescript` (pack contents change; check the registry).
- **CodeQL** (`security-extended` suite): `js/missing-token-validation`, `js/path-injection`, `js/request-forgery`, `js/server-side-unvalidated-url-redirection`, `js/cors-misconfiguration-for-credentials`; `py/csrf-protection-disabled`, `py/full-ssrf`, `py/partial-ssrf`, `py/path-injection`; `java/spring-disabled-csrf-protection`, `java/ssrf`, `java/path-injection`, `java/zipslip`. Example: `codeql database create db --language=javascript-typescript && codeql database analyze db codeql/javascript-queries:codeql-suites/javascript-security-extended.qls --format=sarif-latest --output=a01.sarif`.
- **gosec:** `gosec ./...`. Rules: G107/G704 (SSRF), G304/G703 (path traversal), G305 (zip slip), G710 (open redirect), G121 (unsafe CrossOriginProtection bypass patterns).
- **Bandit:** `bandit -r .`. B310 (urllib urlopen scheme audit).
- **SCA:** `osv-scanner scan source -r .`, `npm audit`, `pip-audit`. These catch framework authz CVEs such as Next.js CVE-2025-29927.
- **DAST (own app):** OWASP ZAP (baseline is passive; the full/active scan only against local or staging) plus the ZAP Access Control Testing add-on. Burp Suite extensions Autorize / AuthMatrix for two-user replay. Nuclei `-t http/vulnerabilities/generic/cors-misconfig.yaml`.
- **Tests:** the most reliable detector is an authz matrix in the test suite (roles × endpoints × own/other object → expected status).

### Fix / remediation
- Deny by default. Add one centralized policy layer (guard, policy, DAL). Scope every query by owner or tenant. Enforce field-level allowlists (DTOs).
- CSRF: use the framework's built-in protection; token (synchronizer or signed double-submit) and/or Fetch Metadata (`Sec-Fetch-Site`) with an Origin fallback. `SameSite=Lax/Strict` is defense-in-depth only. No state-changing GET.
- SSRF: accept IDs or allowlisted hosts, not raw URLs. Allow only http/https. Resolve DNS and reject private, loopback, link-local and metadata ranges (169.254.169.254, 127/8, 10/8, 172.16/12, 192.168/16, ::1, fc00::/7). Connect to the vetted IP, disable redirects, and apply egress firewall rules. Use IMDSv2.
- Path: use server-generated names, a traversal-safe API (Go `os.OpenInRoot`, Express `res.sendFile(name, { root })`, Flask `send_from_directory`), or canonicalize and check the prefix.
- Sessions/JWT: destroy server-side sessions on logout. Keep access tokens short-lived and revoke refresh tokens with a `jti` denylist. Pin algorithms and validate `aud`/`iss`/`exp`.

Express: IDOR
```js
// BAD
app.get('/api/orders/:id', auth, async (req, res) => res.json(await Order.findByPk(req.params.id)));
// GOOD: scope to owner; 404 hides existence
app.get('/api/orders/:id', auth, async (req, res) => {
  const o = await Order.findOne({ where: { id: req.params.id, userId: req.user.id } });
  return o ? res.json(toOrderDTO(o)) : res.sendStatus(404);
});
```
Django REST Framework: global deny-by-default plus scoped queryset
```python
# settings.py
REST_FRAMEWORK = {"DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"]}
# views.py  BAD: queryset = Invoice.objects.all()
class InvoiceViewSet(viewsets.ModelViewSet):
    serializer_class = InvoiceSerializer            # fields = explicit allowlist, read_only_fields=["owner"]
    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)
    def perform_create(self, s): s.save(owner=self.request.user)
```
Spring Security: deny by default plus an ownership check at the method level
```java
http.authorizeHttpRequests(a -> a.requestMatchers("/public/**").permitAll()
                                 .requestMatchers("/admin/**").hasRole("ADMIN")
                                 .anyRequest().authenticated());      // not permitAll()
@PreAuthorize("@orderAuthz.isOwner(#id, authentication)")            // with @EnableMethodSecurity
@GetMapping("/orders/{id}") OrderDto get(@PathVariable Long id) { ... }
```
Python: SSRF guard (outline)
```python
import ipaddress, socket, urllib.parse
def safe_target(url, allowed_hosts):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("https",) or u.hostname not in allowed_hosts: raise ValueError("host not allowed")
    for *_, sa in socket.getaddrinfo(u.hostname, u.port or 443):
        if not ipaddress.ip_address(sa[0]).is_global: raise ValueError("non-public IP")
    return u   # then connect to the vetted IP, with allow_redirects=False and a timeout
```

### Best-practice checklist
- [ ] Every non-public route is denied by default via a global guard or fallback policy (ASVS 8.2.1, 8.3.1).
- [ ] Every object access checks ownership or tenant on the server; list queries are scoped (8.2.2, 8.4.1).
- [ ] Field-level read/write allowlists (DTOs/serializers); no binding of `role`, `ownerId`, `isAdmin` (8.2.3, 15.3.3, 15.3.1).
- [ ] Authorization rules are documented per function, data and field (8.1.1, 8.1.2).
- [ ] Authorization is enforced in trusted server code; UI hiding and edge middleware are only optimistic (8.3.1).
- [ ] Permission changes take effect immediately; no stale role in long-lived tokens (8.3.2).
- [ ] Logout and expiry invalidate the session server-side; disabled users lose all sessions (7.4.1, 7.4.2).
- [ ] JWTs are verified with an allowlisted algorithm (never `none`) and trusted keys; `exp` and `aud` are enforced (9.1.1–9.1.3, 9.2.1, 9.2.3).
- [ ] CSRF is covered for cookie-auth apps; sensitive actions use non-safe methods; cookies have an appropriate SameSite (3.5.1–3.5.3, 3.3.2).
- [ ] CORS `Access-Control-Allow-Origin` is fixed or allowlisted; `*` never with credentials or sensitive data (3.4.2).
- [ ] Outbound requests are allowlisted by protocol, host, port and path; redirects off; egress restricted (1.3.6, 13.2.4, 13.2.5).
- [ ] File paths come from server-generated names; archive extraction ignores embedded paths (5.3.2, 5.3.3).
- [ ] Off-site redirects are allowlisted only (3.7.2).
- [ ] No `.git`, directory listings or source maps in the web root (13.4.1, 13.4.3).
- [ ] Failed authorization attempts are logged and alerted on (16.3.2). Rate limits apply to APIs.
- [ ] CI runs an authz matrix: negative tests for cross-user, cross-tenant and role escalation.

### Severity guidance
- **Critical:** Unauthenticated access to admin functions or to any user's data. IDOR with read/write/delete on sensitive data with enumerable IDs, or cross-tenant access. JWT signature not verified or `alg:none` accepted. Authz only in bypassable middleware (e.g. unpatched CVE-2025-29927). SSRF that reaches cloud metadata, internal admin APIs or credentials. Path traversal that reads `.env`/keys or writes files. CORS reflecting any origin with credentials on an authenticated API holding sensitive data.
- **High:** Authenticated horizontal IDOR on PII or financial data. Vertical escalation (user to admin function). Mass assignment of `role`/`ownerId`. CSRF on account takeover-relevant actions (email/password change, payments, admin ops). Blind SSRF to the internal network. Logout that does not invalidate sessions combined with long-lived tokens.
- **Medium:** IDOR on low-sensitivity data, or where only non-guessable IDs protect the object (still a real finding). CSRF on low-impact state changes. Open redirect (raise to High if it feeds an OAuth `redirect_uri` or token flow). Directory listing of non-sensitive files. Missing rate limiting on object endpoints.
- **Low:** Existence oracle (403 vs 404). Sensitive info in source comments. Authz failures not logged. Missing explicit SameSite where the browser Lax default applies.
- Adjust: +1 level for multi-tenant or regulated data; −1 if exploitation needs an unlikely precondition (e.g. an admin-only account already compromised).

### Sources
- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A01_2025-Broken_Access_Control.md
- https://owasp.org/Top10/2025/0x00_2025-Introduction/
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A07_2025-Authentication_Failures.md
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
- https://github.com/OWASP/ASVS (5.0.0, May 2025); https://github.com/OWASP/ASVS/blob/master/5.0/en/0x17-V8-Authorization.md
- ASVS 5.0 chapters V1, V3, V5, V7, V9, V13, V15, V16: https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/README
- https://nextjs.org/docs/app/guides/authentication ; https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
- https://www.django-rest-framework.org/api-guide/permissions/
- https://laravel.com/docs/authorization ; https://laravel.com/docs/csrf
- https://learn.microsoft.com/en-us/aspnet/core/security/authorization/secure-data
- https://go.dev/doc/go1.25 (CrossOriginProtection) ; https://go.dev/blog/osroot
- https://github.com/expressjs/cors ; https://raw.githubusercontent.com/encode/starlette/master/starlette/middleware/cors.py
- https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/python/django/security/audit/csrf-exempt.yaml
- https://raw.githubusercontent.com/semgrep/semgrep-rules/develop/java/spring/security/audit/spring-csrf-disabled.yaml
- https://codeql.github.com/codeql-query-help/javascript/ ; https://codeql.github.com/codeql-query-help/python/ ; https://codeql.github.com/codeql-query-help/java/
- https://raw.githubusercontent.com/securego/gosec/master/RULES.md
- https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html
- https://docs.projectdiscovery.io/opensource/nuclei/running
