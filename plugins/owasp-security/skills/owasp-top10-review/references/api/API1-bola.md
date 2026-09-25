## API1:2023 – Broken Object Level Authorization
**Edition notes:** Unchanged from API1:2019 and still #1. Official rating: exploitability Easy, prevalence Widespread, detectability Easy, technical impact Moderate. An Aug 2026 `develop`-branch note (not yet on the live site) says UUIDs reduce enumeration, but a leaked ID is public, and authorization "must never rely on the secrecy or unpredictability of object identifiers".
**Maps to Top 10:2025: A01** (Broken Access Control). CWE-639, CWE-566, CWE-285, CWE-862 and CWE-863 are all in the A01:2025 list, and A01's description names IDOR.

### What it is (issue)
An endpoint takes an object ID from the client and then reads, changes or deletes that object without checking that the caller may act on *that specific object*. The ID can arrive in the path, query, header, body, a GraphQL argument or a gRPC message field. The caller is allowed to use the function. The failure is only at the object level; if the caller should not reach the function at all, it is API5 (BFLA). OWASP notes that comparing the user ID in the JWT with the ID parameter "could address only a small subset of cases". It misses shared, hierarchical and multi-tenant objects.

### Root causes
- Authorization stops at "is authenticated" or route middleware. No per-object policy runs after the record is loaded.
- Records are looked up by primary key alone (`findById(id)`). Each handler author must remember the owner/tenant filter, and there is no central data-access layer or policy engine.
- Owner or tenant IDs come from the client (`?userId=`, `X-Tenant-Id`, body `accountId`) instead of from the authenticated principal.
- The same object has several entry points (REST, GraphQL `node(id:)`, gRPC, Next.js Server Actions, bulk/export, webhooks, jobs) and only some check it. Nested resources (`/orgs/{o}/projects/{p}`) check the parent but not that the child belongs to it.
- Unguessable IDs are treated as the control. IDs leak through other responses, logs, URLs and emails.
- There are no negative tests (user A requesting user B's object).

### Key CWEs
- ★ **CWE-639** Authorization Bypass Through User-Controlled Key (official ref)
- ★ **CWE-285** Improper Authorization (official ref)
- ★ **CWE-566** Authorization Bypass Through User-Controlled SQL Primary Key
- ★ **CWE-862** Missing Authorization · ★ **CWE-863** Incorrect Authorization
- CWE-284 Improper Access Control (parent class)

### How to detect — code review
**Stack-agnostic:** List every entry point that accepts an ID: routes/controllers, GraphQL resolvers (including `node`/`nodes` and nested edges), gRPC methods, Next.js `route.ts` and `"use server"` files, webhooks and jobs. For each one, answer three questions. Where does the ID come from? Where is the record loaded or mutated (`UPDATE/DELETE ... WHERE id = ?`)? Is the record tied to the principal (owner, tenant or object ACL) *before* the response or the write? Also flag list endpoints that filter by a client-supplied `userId`/`tenantId`.
- **Node (Express/Nest/Next + Prisma/Mongoose/TypeORM):** `findUnique\(\{\s*where:\s*\{\s*id:\s*(req\.|params\.|body\.|args\.)` · `findById\(\s*req\.(params|query|body)` · `\.(update|delete)(Many)?\(\{\s*where:\s*\{\s*id:` with no `userId|ownerId|tenantId` in the same `where` · `req\.(query|body)\.(userId|tenantId|accountId)` used in a query.
- **Python:** `objects\.get\(\s*(pk|id)\s*=` · `get_object_or_404\(\s*\w+\s*,\s*(pk|id)\s*=[^,)]*\)` (no owner kwarg) · DRF `queryset\s*=\s*\w+\.objects\.all\(\)` with no `get_queryset` override and no object permission. DRF only calls `has_object_permission` via `get_object()`, so custom `@action`s that query directly skip it. FastAPI/Flask: `session\.get\(\w+,\s*\w*_?id\)` or `filter_by\(id=` without a user filter.
- **Java (Spring):** `findById\(\s*\w*[iI]d\s*\)` in `@PathVariable` handlers where `@PreAuthorize` checks only the role. Look for a missing `@PostAuthorize("returnObject.owner == authentication.name")` or a missing scoped query (`findByIdAndOwnerId`).
- **Go:** an ID from `r\.PathValue\(|chi\.URLParam\(|mux\.Vars\(|c\.Param\(` flows into `QueryRow|\.First\(&\w+,\s*\w*[iI][dD]\)` with no `user_id`/`tenant_id` predicate.
- **PHP (Laravel):** `::(find|findOrFail)\(\s*\$(id|request)` or implicit route-model binding with no `Gate::authorize|\$this->authorize|->can\(|authorizeResource` or Policy. Nested routes without `->scopeBindings()`.
- **.NET:** `\.(Find|FindAsync|FirstOrDefaultAsync|SingleOrDefaultAsync)\(\s*(id|\w+ => \w+\.Id == \w*[iI]d)\)` with no owner predicate and no `IAuthorizationService.AuthorizeAsync(User, entity, ...)`. EF Core global query filters mitigate this; flag `IgnoreQueryFilters\(\)`.
- **GraphQL / gRPC:** GraphQL authz that exists only on the root query field, not on `node` or child edges. gRPC interceptors only see method names, so object checks must live in the handler; look for `*_id` fields used directly.
- **False positives:** IDs taken from the session (`/me`, `req.user.id`); objects that are public by design; ownership enforced downstream (repository/DAL, Postgres row-level security, ORM tenant filters, OPA/Cedar/OpenFGA calls). Trace the call before flagging.

### How to detect — runtime (safe, own app only)
- Create an object as B, then read it as A: `curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TA" localhost:8080/api/orders/$B_ORDER`. Expect 403/404, never 200 with B's data. Repeat PUT/PATCH/DELETE against a throwaway object, then re-GET as B to confirm nothing changed.
- Cross-tenant: repeat with `$TC`. Try `?userId=$B_ID` or an `X-Tenant-Id` override on list endpoints; the API must ignore or reject them.
- GraphQL: send `{"query":"query($id:ID!){node(id:$id){id}}","variables":{"id":"<B global id>"}}` with `$TA`. Expect `null` or an error.
- gRPC: `grpcurl -plaintext -H "authorization: Bearer $TA" -d '{"order_id":"'$B_ORDER'"}' localhost:50051 shop.v1.Orders/GetOrder` should return `PermissionDenied` or `NotFound`.
- Encode the user × object × verb matrix as integration tests in CI.

### Tools
- SAST coverage is weak here. Write custom Semgrep rules for bare-ID ORM lookups. CodeQL has `cs/web/insecure-direct-object-reference` (C#).
- Spectral with `@stoplight/spectral-owasp-ruleset` v2 (`owasp:api1:2023-no-numeric-ids`): `spectral lint openapi.yaml`.
- DAST/manual: Burp **Autorize** / AuthMatrix, the ZAP Access Control Testing add-on, and Schemathesis v4 stateful checks (`use_after_free`, `ensure_resource_availability`): `schemathesis run openapi.yaml --url http://localhost:8080 -H "Authorization: Bearer $TA" --checks all`. Cross-user checks still need your own two-user test matrix.

### Fix / remediation
Either load the record and then authorize it, or scope the query by the principal. Do it in one central layer (a DAL or policy service), not in each handler.
```ts
// Express+Prisma — bad
const o = await prisma.order.findUnique({ where: { id: req.params.id } });
// good: scope by principal; 404 on miss avoids leaking existence
const o = await prisma.order.findFirst({ where: { id: req.params.id, userId: req.user.id } });
if (!o) return res.sendStatus(404);
```
```python
# Django — bad: get_object_or_404(Order, pk=pk)
order = get_object_or_404(Order, pk=pk, owner=request.user)   # DRF: filter in get_queryset()
```
```java
// Spring — good
Order o = repo.findByIdAndOwnerId(id, principal.getId()).orElseThrow(NotFoundException::new);
```
Also: take tenant and owner from the token, never from the request. Apply the same policy on every transport (REST, GraphQL resolvers, gRPC handlers, Server Actions). Add DB row-level security as defense in depth. Keep random IDs, but never rely on them as the control.

### Best-practice checklist
- [ ] Every function that takes an object ID runs a data-specific authorization check (ASVS 8.2.2).
- [ ] Authorization is enforced in a trusted server-side layer (8.3.1), and the rules are documented (8.1.1).
- [ ] Multi-tenant apps enforce cross-tenant isolation on every query (8.4.1).
- [ ] Owner/tenant comes from the authenticated principal. Client-supplied owner fields are ignored.
- [ ] GraphQL `node`/`nodes` and child edges, gRPC methods, and bulk/export/webhook paths are all covered.
- [ ] Failed authorization attempts are logged (16.3.2). A→B and A→C negative tests run in CI.

### Severity guidance
- **Critical:** read or write of other users' or tenants' sensitive data at scale (enumerable IDs; PII, financial or health data), or BOLA on account settings leading to account takeover.
- **High:** modify or delete other users' objects; cross-tenant access; sensitive reads where the IDs are not enumerable but leak elsewhere.
- **Medium:** reading other users' low-sensitivity objects, or exploitation needs IDs that are hard to obtain.
- **Low:** existence disclosure only (403 vs 404) or non-sensitive metadata.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/ (live site); repo `develop` branch `editions/2023/en/0xa1-...md` (GUID note)
- https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/ · https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html · ASVS 5.0 V8 (github.com/OWASP/ASVS `5.0/en/0x17-V8-Authorization.md`)
- https://nextjs.org/docs/app/guides/data-security · github.com/github/codeql (`csharp/ql/src/Security Features/CWE-639`) · npm `@stoplight/spectral-owasp-ruleset` 2.0.1 · PyPI schemathesis 4.28

---
