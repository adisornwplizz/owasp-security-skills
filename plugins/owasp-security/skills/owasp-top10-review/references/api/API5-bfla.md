## API5:2023 – Broken Function Level Authorization
**Edition notes:** Same name and position as API5:2019, and the text is substantively unchanged. Official rating: exploitability Easy, prevalence Common, detectability Easy, impact Severe.
**Maps to Top 10:2025: A01** (Broken Access Control). CWE-285, 862, 863, 425 (Forced Browsing) and 749 (Exposed Dangerous Method) are A01:2025, and A01 lists "missing access controls for POST, PUT, and DELETE" and force browsing. Privilege-model design flaws (CWE-269) map to A06:2025.

### What it is (issue)
A caller reaches a *function* that their role or group should not be able to invoke. Functions include endpoints, HTTP methods, GraphQL mutations or fields, gRPC methods, Server Actions and job triggers. Official examples:
- A regular user calls `POST /api/invites/new` with `"role":"admin"`.
- An attacker guesses `GET /api/admin/v1/users/all`.
- Switching `GET` to `DELETE` on the same path works.

It differs from BOLA: here the whole function is off-limits, not just one object. OWASP warns: "Don't assume that an API endpoint is regular or administrative only based on the URL path."

### Root causes
- Routing allows by default: authz is added by hand per route, new routes ship unprotected, and there is no global guard or fallback policy.
- Authentication is mistaken for authorization: `authenticated()`-only rules, and role checks that exist only in the UI.
- Admin functions sit next to user functions (`/api/users/export_all`). Rules are method-specific (GET protected, DELETE not) or prefix-based (`/admin/**`) and miss path variants and versions.
- Role hierarchies are complex, and invite/registration/update flows accept a client-supplied role.
- Other transports are not covered: GraphQL mutations, gRPC admin RPCs, grpc-gateway REST mappings, Next.js Server Actions and websockets.
- Auth lives only in middleware. Example: Next.js CVE-2025-29927 bypassed authorization done in middleware; fixed in 12.3.5 / 13.5.9 / 14.2.25 / 15.2.3.
- Debug, internal and management endpoints (actuator, `/internal/*`) are exposed.

### Key CWEs
- ★ **CWE-285** Improper Authorization (official) · ★ **CWE-862** Missing Authorization · ★ **CWE-863** Incorrect Authorization
- ★ **CWE-425** Direct Request ('Forced Browsing') · ★ **CWE-749** Exposed Dangerous Method or Function
- ★ **CWE-269** Improper Privilege Management (role-grant flows) · CWE-306 Missing Authentication for Critical Function

### How to detect — code review
**Stack-agnostic:**
1. Build a function inventory: `php artisan route:list`, django-extensions `show_urls`, the OpenAPI spec, the GraphQL SDL, `.proto` services, and Next.js `app/**/route.ts` plus `"use server"` files.
2. Annotate each function with its required role and diff that against the guards actually applied.
3. Confirm deny-by-default (a global guard or fallback policy), then review every opt-out (`@Public`, `AllowAnonymous`, `permitAll`, `AllowAny`).
4. Check that role-grant flows (invites, member/role updates) verify the caller may grant the target role.
- **Node:** `router\.(get|post|put|patch|delete)\(\s*['"][^'"]*(admin|internal|export|impersonat|role|permission)` without `requireRole|authorize|isAdmin|can\(` in the handler chain · Nest guards not registered as `APP_GUARD`, controllers without `@UseGuards(RolesGuard)`/`@Roles(`, `@Public\(\)` · Next.js auth only in `middleware.ts`/`proxy.ts` matchers, and `route.ts`/`"use server"` code with no `auth()` or role check inside.
- **Python:** DRF `permission_classes\s*=\s*\[\s*(AllowAny)?\s*\]`, or no `DEFAULT_PERMISSION_CLASSES` at all (the DRF default is `AllowAny`) · admin viewsets with only `IsAuthenticated` · Django views without `@login_required|@permission_required|@user_passes_test|PermissionRequiredMixin` · FastAPI routes without `Depends\(get_current_\w+\)|Security\(.*scopes=` · Flask routes without `@login_required|@roles_required`.
- **Java:** `\.permitAll\(\)` on broad matchers · `anyRequest\(\)\.(permitAll|authenticated)\(\)` with no role rules for admin paths · `requestMatchers\(HttpMethod\.GET,` guarding only one method · `@PreAuthorize` used without `@EnableMethodSecurity` · `management\.endpoints\.web\.exposure\.include\s*=\s*\*`.
- **Go:** `HandleFunc\(\s*"/(admin|internal)` not wrapped in auth middleware · chi routes outside a `r.Group` with `r.Use(requireAdmin)` · gRPC admin methods with no authz interceptor (`authz.NewStatic` policy or a custom one) · `reflection\.Register\(` in production builds.
- **PHP/Laravel:** routes outside `Route::middleware\(\[.*auth` groups · admin routes without `can:` middleware or `Gate::authorize` · `Route::(any|match)\(`.
- **.NET:** `\[AllowAnonymous\]` · controllers without `[Authorize(Roles|Policy)]` · minimal APIs `Map(Get|Post|Put|Delete|Patch)\(` without `.RequireAuthorization\(` · no `FallbackPolicy` · gRPC services without `[Authorize]`.
- **GraphQL:** mutations and admin fields without resolver-level role checks; introspection enabled in production exposes admin operations (Apollo disables it by default only when `NODE_ENV=production`).
- **False positives:** authz enforced by a gateway or service mesh (Envoy RBAC, OPA sidecar; verify the config); intentionally public endpoints (health, login, docs in dev).

### How to detect — runtime (safe, own app only)
- For each privileged function in the inventory: no token → 401; `$TA` → 403. Example: `curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TA" localhost:8080/api/admin/v1/users/all`.
- **Method switching:** `-X DELETE|PUT|PATCH` on user-reachable paths should return 403/405. Path variants (trailing slash, case, `/v1` vs `/v2`) must behave the same way.
- **Role grants:** as a regular user, send `POST /api/invites {"email":"qa+1@example.test","role":"admin"}`. Expect 403 or the role ignored; verify in the admin view.
- **GraphQL:** admin mutations with `$TA` → error. **gRPC:** `grpcurl -H "authorization: Bearer $TA" ... admin.v1.Admin/ListUsers` → `PermissionDenied`. Reflection should be unavailable in production-like builds.
- **Next.js:** invoke Server Actions and route handlers directly, not through the page, as a low-privilege user. They must be rejected.
- Encode the role × endpoint × method matrix as CI tests.

### Tools
- **Semgrep:** `csharp.dotnet.security.audit.missing-or-broken-authorization` (CWE-862), plus custom "route without guard" rules per framework. **CodeQL:** `cs/web/missing-function-level-access-control`, `java/spring-boot-exposed-actuators-config`.
- **Spectral OWASP:** `owasp:api5:2023-admin-security-unique` (admin operations need a distinct security scheme), and `owasp:api2:2023-read-restricted`/`-write-restricted` (every operation declares security).
- **DAST:** Burp Autorize/AuthMatrix, the ZAP Access Control Testing add-on, Schemathesis `--checks ignored_auth`, and `grpcurl list` in staging.

### Fix / remediation
```ts
// NestJS — deny by default with global guards; explicit roles per handler
providers: [{ provide: APP_GUARD, useClass: JwtAuthGuard }, { provide: APP_GUARD, useClass: RolesGuard }]
@Roles('admin') @Get('admin/users') listAll() {}
```
```java
// Spring Security 6/7 — path rules + method security
http.authorizeHttpRequests(a -> a.requestMatchers("/api/admin/**").hasRole("ADMIN")
    .requestMatchers("/api/public/**").permitAll().anyRequest().authenticated());
@EnableMethodSecurity   // and @PreAuthorize("hasRole('ADMIN')") on admin services
```
```csharp
// ASP.NET Core — fallback policy + named policies
builder.Services.AddAuthorizationBuilder()
  .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
  .AddPolicy("Admin", p => p.RequireRole("admin"));
app.MapGet("/api/admin/users", ListUsers).RequireAuthorization("Admin");
```
Also:
- Admin controllers inherit from a base admin controller that performs role checks (official advice).
- Validate role grants server-side.
- Separate the admin API by audience, security scheme or host.
- Disable gRPC reflection and GraphQL introspection in production.
- Re-check authz inside every Server Action or handler, not only in middleware.

### Best-practice checklist
- [ ] Function-level access is restricted to explicit permissions (ASVS 8.2.1), the rules are documented (8.1.1), and they are enforced server-side (8.3.1).
- [ ] Deny by default: a global guard or fallback policy exists, and every public opt-out is reviewed.
- [ ] Every method on every path is authorized, and unused HTTP methods are blocked (4.1.4, L3).
- [ ] Admin interfaces have layered controls (8.4.2, L3). GraphQL introspection is off in production unless the API is public (4.3.2).
- [ ] Role grants are validated, and authz changes take effect immediately (8.3.2).
- [ ] Failed authorization attempts are logged (16.3.2), and role × endpoint tests run in CI.

### Severity guidance
- **Critical:** an anonymous or regular user can run admin or privilege-management functions (create admins, change roles, impersonate, export all users, change config).
- **High:** a regular user can perform privileged writes/deletes or bulk exports; method switching bypasses authz on sensitive resources; auth that lives only in middleware can be bypassed.
- **Medium:** privileged read-only functions leak limited data; internal or debug endpoints expose moderate information.
- **Low:** admin functions with no sensitive effect; discoverability only (reflection or introspection in staging).

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/ · https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
- https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html · ASVS 5.0 V4, V8, V16
- https://nvd.nist.gov/vuln/detail/CVE-2025-29927 · https://nextjs.org/docs/app/guides/data-security
- grpc-go `authz` package (`NewStatic`, `NewFileWatcher`) · github.com/github/codeql · github.com/semgrep/semgrep-rules · npm `@stoplight/spectral-owasp-ruleset`
