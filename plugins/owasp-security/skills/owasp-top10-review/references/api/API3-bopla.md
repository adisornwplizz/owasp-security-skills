## API3:2023 – Broken Object Property Level Authorization
**Edition notes:** New in 2023. It merges API3:2019 Excessive Data Exposure (read side) and API6:2019 Mass Assignment (write side) under one root cause: missing authorization at the property level. Official rating: exploitability Easy, prevalence Common, detectability Easy, impact Moderate.
**Maps to Top 10:2025: A01 + A08.** The read side maps to A01 (CWE-200, 201 and 359 are A01:2025). The write side maps to **A08** (Software or Data Integrity Failures), because CWE-915 sits in A08:2025. CWE-213 is not mapped in 2025, and CWE-472 is in A06.

### What it is (issue)
The caller may access the object, but not every property of it.
- **Read side:** the API returns sensitive or internal properties (password hash, role, internal flags, another user's PII or location) because it serializes whole objects and leaves filtering to the client.
- **Write side:** the API binds client input onto internal objects, so extra properties get written. Common targets: `role`, `isAdmin`, `price`, `blocked`, `ownerId`, `tenantId`, `emailVerified`.

### Root causes
- ORM entities or `to_json()`/`model_dump()` are returned as-is, on the assumption that "the frontend only shows what it needs".
- Request bodies are auto-bound to domain/ORM models (`Model.create(req.body)`, `@RequestBody Entity`, `$request->all()`), and denylists are used instead of allowlists.
- One DTO serves create, update, read and admin views, so there are no per-role field rules (for example, the owner may see `phone` but others may not).
- GraphQL schemas are generated from DB models without field-level authz, and input types mirror the models.
- Protobuf storage messages are reused as API responses, and update RPCs have no field-mask allowlist.
- Unexpected input fields are neither rejected nor logged.

### Key CWEs
- ★ **CWE-213** Exposure of Sensitive Information Due to Incompatible Policies (official)
- ★ **CWE-915** Improperly Controlled Modification of Dynamically-Determined Object Attributes (official; mass assignment)
- ★ **CWE-200** Exposure of Sensitive Information to an Unauthorized Actor · ★ **CWE-201** … Through Sent Data · ★ **CWE-359** Private Personal Information
- CWE-472 External Control of Assumed-Immutable Web Parameter · CWE-1321 Prototype Pollution (Node, related)

### How to detect — code review
**Stack-agnostic:** For every response, find its serializer or DTO. Flag whole-entity returns and denylist filtering (`exclude=`, or `@JsonIgnore` on only a few fields). For every create/update, find how input maps onto the model. Flag bulk binding and any path that lets a non-privileged caller write sensitive columns: role/permissions, status, price/amount, owner/tenant IDs, verification flags, counters. Diffing the DB columns against the DTO fields is a fast first pass.
- **Node:** `res\.(json|send)\(\s*(user|account|await\s+\w+\.(find\w*))` · `Object\.assign\(\s*\w+\s*,\s*req\.body` · `\.\.\.req\.body` · `data:\s*req\.body` (Prisma) · `\.(create|update|findByIdAndUpdate|updateOne)\([^)]*req\.body` · Nest `ValidationPipe\(` without `whitelist:\s*true` · a missing `ClassSerializerInterceptor`/`@Exclude()`. Next.js: Server Actions that return DB records, and `'use client'` props typed as the full model.
- **Python:** `fields\s*=\s*['"]__all__['"]` (DRF/ModelForm) · `\*\*request\.(data|POST|json)` · `setattr\(\w+,\s*\w+,\s*\w+\)` in loops over request data · FastAPI handlers returning ORM objects without `response_model` · SQLModel `table=True` models used as request bodies.
- **Java:** `@RequestBody\s+\w*(Entity|User|Account)\b` binding a JPA entity · `@ModelAttribute` without `@InitBinder` `setAllowedFields` · `BeanUtils\.copyProperties\(\s*(req|dto|body|input)` · `@RestController` methods returning `@Entity` types.
- **Go:** `json\.NewDecoder\(r\.Body\)\.Decode\(&(u|user|acct|m)\)` into a gorm model · gin `ShouldBind(JSON)?\(&\w+\)` into DB structs · `\.Updates\(\s*(input|req|body)\)` · model structs with a `json:"password` tag or without `json:"-"` on secrets.
- **PHP/Laravel:** `\$guarded\s*=\s*\[\s*\]` · `Model::unguard\(` · `->(fill|update|create|forceFill)\(\s*\$request->all\(\)\s*\)` · returning models without `$hidden` or API Resources.
- **.NET:** `\[FromBody\]\s*\w*(Entity|User|Account)\b` binding an EF entity · `TryUpdateModelAsync\(\w+\)` with no property list · `return Ok\(await _\w+\.\w+\.` returning entities directly.
- **GraphQL / gRPC:** sensitive fields without field-level authz (resolver or directive); mutation input types containing `role`/`isAdmin`/`ownerId`. gRPC update RPCs without a `google.protobuf.FieldMask` (AIP-134) checked against an allowlist.
- **False positives:** admin-only endpoints (verify the admin authz); explicit DTOs; silently ignoring unknown fields is safe as long as the target type has no sensitive fields.

### How to detect — runtime (safe, own app only)
- **Read:** as a low-privilege user, fetch your own object and another user's public object, e.g. `curl -s -H "Authorization: Bearer $TA" localhost:8080/api/users/$B_ID | jq 'keys'`. Compare the keys with the documented schema. Flag `password*`, `*hash*`, `token`, `secret`, `role`, `is_admin`, `internal*`, and other users' email, phone or location.
- **Write:** replay a legitimate update on your own object with one extra property added: `curl -X PATCH -H "Authorization: Bearer $TA" -H 'Content-Type: application/json' -d '{"displayName":"x","role":"admin"}' localhost:8080/api/users/me`. Expect 400 or the field ignored, then re-GET to confirm `role` is unchanged. Repeat with `isVerified`, `ownerId`, `price`, `status`.
- **GraphQL:** as user A, query sensitive fields on another user (`user(id:){email phone}`) and expect null or an error. In staging, use introspection to list fields per type for review.
- **Schema drift:** Schemathesis `response_schema_conformance` only flags undocumented properties when schemas set `additionalProperties: false`.

### Tools
- **Semgrep:** `python.django.security.injection.mass-assignment`, `php.laravel.security.laravel-dangerous-model-construction` (flags `$guarded = []`), `javascript.express.security.express-data-exfiltration` (`Object.assign` with user data), `csharp.dotnet.security.audit.mass-assignment`.
- **CodeQL:** `js/prototype-polluting-assignment` and related CWE-915 queries (narrow: prototype pollution only).
- **Spectral OWASP:** `owasp:api3:2023-no-additional`, `-constrained-additional`, `-no-unevaluated`, `-constrained-unevaluated`. These enforce closed request/response schemas.
- **DAST:** Burp Param Miner (hidden parameters) and ZAP with an authenticated context. Diff actual responses against the OpenAPI schema.

### Fix / remediation
```ts
// NestJS — allowlist input DTO, reject unknown fields, explicit response shape
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));
class UpdateProfileDto { @IsString() @MaxLength(50) displayName: string }   // no role/isAdmin
return { id: u.id, displayName: u.displayName };                            // not `return u`
```
```python
# DRF — bad: fields = "__all__"
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User; fields = ["id", "display_name", "email"]; read_only_fields = ["id", "email"]
```
```php
// Laravel — bad: $user->update($request->all());
$user->update($request->validated());   // FormRequest rules act as the allowlist; model: $fillable
// dev/test: Model::preventSilentlyDiscardingAttributes() (or Model::shouldBeStrict())
```
Other stacks:
- **Go:** separate request structs, `dec.DisallowUnknownFields()`, and `json:"-"` on secrets.
- **Spring:** request/response `record` DTOs; never bind an `@Entity`.
- **.NET:** input DTOs, `[JsonIgnore]`, and `JsonUnmappedMemberHandling.Disallow` (.NET 8+).
- **GraphQL:** field-level authz plus separate input types.
- **gRPC:** a field-mask allowlist on updates.

### Best-practice checklist
- [ ] Field-level read and write rules are documented per role (ASVS 8.1.2) and enforced (8.2.3).
- [ ] Responses contain only the required fields (15.3.1), and sensitive data is minimized or masked (14.2.6, L3).
- [ ] Mass-assignment defenses limit the allowed fields per action (15.3.3).
- [ ] Create, update, read and admin each have their own DTO, built from allowlists.
- [ ] OpenAPI uses `additionalProperties: false`, and tests validate response schemas.
- [ ] GraphQL has field-level authz, and gRPC update masks are allowlisted.

### Severity guidance
- **Critical:** writable privilege fields (`role`, `isAdmin`, `permissions`, `tenantId`, `ownerId`) leading to privilege escalation or account takeover; exposure of password hashes, secrets or tokens.
- **High:** writable financial or state fields (price, balance, approval, `blocked`, `emailVerified`); bulk exposure of other users' sensitive PII (location, phone, government ID).
- **Medium:** exposure of internal fields with limited sensitivity; writable non-security metadata that breaks integrity.
- **Low:** non-sensitive internal attributes (timestamps, internal IDs) that only help recon.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/
- https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html · https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/
- ASVS 5.0 V8, V14, V15 · https://nextjs.org/docs/app/guides/data-security · https://google.aip.dev/134
- github.com/semgrep/semgrep-rules · npm `@stoplight/spectral-owasp-ruleset` 2.0.1

---
