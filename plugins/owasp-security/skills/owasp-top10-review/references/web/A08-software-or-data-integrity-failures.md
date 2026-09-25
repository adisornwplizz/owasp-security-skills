## A08:2025 – Software or Data Integrity Failures
**Edition notes:**
- Stays at #8. The name changed slightly from "Software **and** Data Integrity Failures" (2021) to "Software **or** Data Integrity Failures". The category absorbed A8:2017 Insecure Deserialization in 2021, and that remains its best-known CWE (CWE-502).
- 14 CWEs mapped, 3,331 CVEs. Max incidence 8.98%, average incidence 2.75%, average coverage 45.49%, average weighted exploit 7.11, impact 4.79. OWASP names CWE-829, CWE-915 (mass assignment) and CWE-502 as the notable ones.
- **How it differs from A03:2025 Software Supply Chain Failures.** OWASP describes A08 as operating "at a lower level than Software Supply Chain Failures". A03 is about managing the *ecosystem*: knowing, patching and vetting components; SBOMs; EOL, vulnerable or malicious packages; hardening the build and CI/CD process. A08 is about a *missing integrity or authenticity check at a trust boundary* in your code, config or pipeline, where something is treated as trusted without verification:
  - a script loaded from a CDN with no SRI;
  - `curl | sh` or an auto-updater with no checksum or signature;
  - a native-serialized blob or a role cookie accepted from the client;
  - a webhook processed without HMAC verification;
  - a request body bound straight onto an ORM entity;
  - a workflow that runs fork code with release credentials.

  Rule of thumb: an outdated or malicious component, or weak supply-chain process, is A03. The code or pipeline trusting code or data it never verified is A08.
- Cross-references:
  - CWE-347 (JWT or other signature verification) is mapped to **A04:2025 Cryptographic Failures**.
  - Mass assignment also appears in the API Top 10 as **API3:2023 Broken Object Property Level Authorization**.
  - Prototype pollution (CWE-1321) is a child of CWE-915.
  - React2Shell (CVE-2025-55182) is a CWE-502 root cause that shipped as an A03 component CVE.

### What it is (issue)
Code and infrastructure that fail to protect against invalid or untrusted code or data being treated as trusted and valid. This covers:
- plugins, libraries or scripts pulled from untrusted sources, repositories or CDNs;
- CI/CD pipelines that consume or produce artifacts without integrity checks;
- auto-update without signature verification;
- objects serialized into a structure the client can see and modify (insecure deserialization, which often leads to RCE);
- client-supplied state (cookies, hidden fields, request bodies) that controls security-relevant fields.

### Root causes
- Using native object serialization for data that crosses a trust boundary: Java `Serializable`, Python `pickle`, PHP `serialize`, .NET `BinaryFormatter`, polymorphic JSON/YAML type resolution. These formats let the *sender* choose the types to instantiate.
- Binding request data directly onto persistence or domain objects, with no per-endpoint allowlist of writable fields and no DTOs. This is the framework convenience default.
- Treating "came from our own frontend, cookie, cache, queue or CDN" as proof of authenticity. There is no MAC or signature, or a static or leaked signing key is used (Laravel `APP_KEY`, Django or Flask `SECRET_KEY`).
- Loading executable content at runtime from locations you do not control or have not pinned: third-party `<script>` tags, `curl | bash`, `ADD <url>`, dynamic `require` or `import` of computed paths, plugin directories writable by others.
- CI/CD trust confusion: privileged triggers (`pull_request_target`, `workflow_run`) that execute or cache attacker-controlled code, and artifacts promoted without provenance or signature verification.
- Signature checks implemented incorrectly: non-constant-time compare, parsed JSON re-serialized before the HMAC check, no timestamp or replay window, signature "optional".
- Integrity (the data is unmodified) is confused with confidentiality: encrypting or base64-encoding without authenticating.

### Key CWEs
All 14 officially mapped (★ = top relevance for web/API developers):
- ★ **CWE-502** Deserialization of Untrusted Data
- ★ **CWE-915** Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment/auto-binding; child CWE-1321 prototype pollution)
- ★ **CWE-829** Inclusion of Functionality from Untrusted Control Sphere (third-party scripts or actions, untrusted checkout in CI)
- ★ **CWE-830** Inclusion of Web Functionality from an Untrusted Source (CDN scripts without SRI, delegated subdomains)
- ★ **CWE-494** Download of Code Without Integrity Check (`curl|sh`, updaters, `ADD` URLs)
- ★ **CWE-345** Insufficient Verification of Data Authenticity (unsigned webhooks, callbacks, client state)
- ★ **CWE-565** Reliance on Cookies without Validation and Integrity Checking / **CWE-784** ...in a Security Decision
- **CWE-353** Missing Support for Integrity Check
- **CWE-426** Untrusted Search Path / **CWE-427** Uncontrolled Search Path Element (PATH, module or DLL resolution, and dependency confusion by analogy)
- **CWE-506** Embedded Malicious Code / **CWE-509** Replicating Malicious Code (Virus or Worm)
- **CWE-926** Improper Export of Android Application Components (not applicable to web/API back ends)

### How to detect — code review
**Stack-agnostic signals, and where to look:**
- **Deserialization sinks** in controllers, message consumers (Kafka/RabbitMQ/SQS), cache readers (Redis/Memcached), session stores, and file or model loaders. Ask whether the bytes can come from a client or a lower-trust producer.
- **Binding** in create and update handlers: request body to entity, then save. Look for fields such as `role`, `isAdmin`, `tenantId`, `ownerId`, `price`, `balance`, `emailVerified`, `status`.
- **Client-side state used for decisions**: cookies, hidden inputs, `localStorage`-derived headers, query parameters such as `price` or `role`.
- **Inbound integrations**: webhook and callback routes, signed-URL handlers, SSO/SAML/JWT consumers (cross-reference A04/A07). Find routes with no signature check: `rg -l -i 'webhook' src app routes | xargs -r rg --files-without-match -i '(constructEvent|signature|hmac|timingSafeEqual|compare_digest|FixedTimeEquals|hash_equals|hmac\.Equal|ConstantTimeCompare)'`
- **Third-party browser code** in templates and layouts: scripts or styles without SRI.
  - `rg -nP '<script\b(?![^>]*\bintegrity=)[^>]*\bsrc=["'\'']?(https?:)?//' -g '*.{html,ejs,hbs,njk,jsx,tsx,vue,svelte,php,twig,cshtml,razor,jinja,j2}'`
  - `rg -nP '<link\b(?=[^>]*rel=["'\'']?stylesheet)(?![^>]*\bintegrity=)[^>]*\bhref=["'\'']?(https?:)?//'`
  - Also check for `@latest` or unversioned CDN URLs, and CNAMEs of your domain pointing to vendors (cookie scope).
- **Code downloaded without verification** in Dockerfiles, CI and install scripts:
  - `rg -nP '(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z)?sh\b'`
  - `rg -nP '^\s*ADD\s+(?!.*--checksum=)(\S+\s+)*https?://' -g 'Dockerfile*'`
  - Downloads not followed by `sha256sum -c`, `cosign verify` or `gh attestation verify`.
  - App updaters or plugin installers that fetch code.
- **CI integrity**:
  - `rg -n 'pull_request_target|workflow_run' .github/workflows`, then in the same file look for `rg -nP 'ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref'`. That combination is the critical untrusted-checkout pattern.
  - `actions/cache` or `download-artifact` in release jobs.
  - Expression injection: `rg -nP 'run:.*\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit|discussion)\.'`
- **Search path / dynamic loading**:
  - Non-literal `require(` or `import(` (Node).
  - `sys.path.insert` or `importlib.import_module(<input>)` (Python).
  - `URLClassLoader` (Java), `Assembly.LoadFrom` (.NET).
  - `exec`/`Process.Start` of bare command names while cwd or PATH is attacker-influenced.
  - Plugin directories that are world- or upload-writable.
- **Embedded malicious or obfuscated code** in vendored or third-party code:
  - Invisible Unicode, as used by GlassWorm (Oct 2025): `rg -nP '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FE00}-\x{FE0F}\x{E0100}-\x{E01EF}]' --glob '!*.md'`
  - `eval(atob(` and `Function(Buffer.from(…,'base64'))`.

**Node (Express / NestJS / Next.js)**
- Deserialization and eval: `rg -nP "require\(['\"](node-serialize|serialize-to-js|funcster|cryo)['\"]\)|\.unserialize\(|\beval\(|new Function\(|vm\.run\w*\(|yaml\.load\("`. js-yaml ≥4 `load` is safe; v3 `load` is not. `vm` is not a sandbox.
- Mass assignment: `rg -nP '\b(create|insertOne|insertMany|update\w*|findByIdAndUpdate|findOneAndUpdate|upsert|build|bulkCreate|save|merge|assign)\s*\([^)]*\breq\.(body|query)\b(?!\.)|data\s*:\s*req\.body\b|new\s+[A-Z]\w*\(\s*req\.body\s*\)|\.\.\.req\.body\b|Object\.fromEntries\(\s*formData'`. The last alternative catches Next.js Server Actions passing `formData` into Prisma. Mongoose `strict` drops *unknown* paths only, not `role`.
- NestJS: `rg -nP 'ValidationPipe\((?![^)]*whitelist\s*:\s*true)'`. Without `whitelist` (and `forbidNonWhitelisted`), extra properties survive into the DTO instance.
- Prototype pollution: `_.merge`, `_.defaultsDeep`, `$.extend(true, …)` or recursive merge helpers fed `req.body`; `obj[a][b] = v` with request keys.
- Trusting cookies: `rg -nP 'req\.(cookies|signedCookies)\.(role|isAdmin|is_admin|admin|userId|user_id|uid|price|plan|tier)\b'`. `req.cookies` is unsigned. `signedCookies` is signed but still client-chosen, so use it for integrity only, never as the source of a role.

**Python (Django / FastAPI / Flask)**
- `rg -nP '\b(c?pickle|_pickle|dill|cloudpickle)\.loads?\(|\bshelve\.open\(|jsonpickle\.decode\(|yaml\.unsafe_load\(|yaml\.load\((?![^)]*SafeLoader)|torch\.load\((?![^)]*weights_only\s*=\s*True)|joblib\.load\(|\.load\([^)]*allow_pickle\s*=\s*True|read_pickle\(|marshal\.loads?\('`. PyTorch ≥2.6 defaults `weights_only=True`. Explicit `False` is a finding.
- Mass assignment: `rg -nP "fields\s*=\s*['\"]__all__['\"]|\.objects\.\w+\([^)]*\*\*request\.(data|POST|GET)|setattr\(\s*\w+\s*,\s*(k|key|field|name|attr)\s*,"`. Covers Django ModelForm or DRF ModelSerializer with `__all__` or `exclude=`, and FastAPI/SQLModel using one model for table, create and update (`User(**payload.model_dump())` with `is_admin`).
- Flask sessions are signed but readable. Look for a hard-coded or short `SECRET_KEY` (`rg -n "SECRET_KEY\s*=\s*['\"]"`), and `request.cookies.get('role')`. Django: custom pickle session serializers (`PickleSerializer` was removed in Django 5.0), `signing.loads` with a leaked key.

**Java (Spring Boot)**
- `rg -nP 'new ObjectInputStream\(|\.readObject\(\)|\.readUnshared\(|new XMLDecoder\(|new XStream\(|\.fromXML\(|enableDefaultTyping\(|activateDefaultTyping\(|JsonTypeInfo\.Id\.(CLASS|MINIMAL_CLASS)|SerializationUtils\.deserialize\(|new Yaml\(\s*\)|HessianInput\(|new Kryo\(' -g '*.{java,kt}'`. Also check for the absence of `ObjectInputFilter` or `jdk.serialFilter`.
- Entity binding: `rg -nP '@(RequestBody|ModelAttribute)\s+(@Valid(ated)?\s+)?(?!\w*(Dto|DTO|Request|Form|Command|Payload|Input)\b)[A-Z]\w+\s+\w+' -g '*Controller*.java'`, then confirm the type is an `@Entity`. Also Spring Data REST exposing writable repositories, and a missing `@InitBinder setAllowedFields`. `@CookieValue("role")`.

**Go**
- Binding to models: `rg -nP '\.(ShouldBind(JSON|With)?|BindJSON|Bind)\(&\w+\)|json\.NewDecoder\([^)]*\)\.Decode\(&\w+\)|\.Updates\(\s*(map\[string\]|input|req|body|payload)'`. Flag it when the target is a GORM model with `Role`/`IsAdmin`/`OrgID` and is followed by `db.Save`/`Create`/`Updates`. Check for missing `json:"-"` and `DisallowUnknownFields()`.
- `gob`/`yaml` decoding into `interface{}`/`any` (Semgrep `go-unsafe-deserialization-interface`). HMAC compared with `==` or `bytes.Equal` instead of `hmac.Equal`. Go ≥1.19 `os/exec` refuses PATH hits in the current directory (`exec.ErrDot`), so do not disable that behavior.

**PHP (Laravel)**
- `rg -nP '\bunserialize\s*\((?![^)]*allowed_classes[^)]*false)|\bdecrypt\s*\(\s*\$request|Crypt::decrypt\(|phar://' -g '*.php'`. Laravel `decrypt()` unserializes by default; use `decryptString()`. A leaked `APP_KEY` combined with cookie or session deserialization gives RCE (GitGuardian/Synacktiv 2025: about 260k keys leaked, about 600 apps exploitable). Check `git ls-files | rg '(^|/)\.env$'`.
- Mass assignment: `rg -nP '\$guarded\s*=\s*\[\s*\]|Model::unguard\(|::(create|forceCreate|update|firstOrCreate|updateOrCreate)\(\s*\$request->(all|input|post)\(\)|->(fill|update|forceFill)\(\s*\$request->(all|input|post)\(\)' -g '*.php'`. Also `$_COOKIE['role']`, and auth-relevant cookies listed in the `EncryptCookies::$except` array.

**.NET (ASP.NET Core)**
- `rg -nP 'BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)|SimpleTypeResolver' -g '*.cs'`. BinaryFormatter throws on .NET 9+, so a match means a legacy TFM or a compatibility package.
- Overposting: `rg -nP '\[FromBody\]\s+(?!\w*(Dto|DTO|Request|ViewModel|Command|Input)\b)[A-Z]\w+\s+\w+|TryUpdateModelAsync\(\s*\w+\s*\)' -g '*.cs'`, then confirm it is an EF entity passed to `_context.Update`/`Attach`. Also `Request.Cookies["role"]`.

**False positives:**
- `pickle` or `ObjectInputStream` on data your process wrote to a store only it can write, such as a local file cache. Still Medium if the store (Redis, S3, a queue) is shared with less-trusted services.
- `yaml.load(..., Loader=SafeLoader)`, js-yaml ≥4 `load`, SnakeYAML ≥2.0 `new Yaml()` (global tags blocked by default), Jackson typing restricted by an allowlist `PolymorphicTypeValidator`, `unserialize($x, ['allowed_classes'=>false])`.
- `$request->all()` on a model whose `$fillable` holds only user-editable fields.
- `Object.assign(entity, parsedDto)` where the DTO schema is strict.
- SRI cannot apply to dynamic, vendor-rotated scripts (Stripe.js, Google Tag Manager, reCAPTCHA). ASVS 3.6.1 accepts a documented decision, plus CSP allowlisting.
- Variation selector U+FE0F appears in normal emoji text.

### How to detect — runtime (safe, own app only)
- **Spot serialized blobs.** Inspect your own cookies, hidden fields, headers and API payloads:
  - `curl -s -c jar.txt -b jar.txt http://localhost:8000/ -o /dev/null && cat jar.txt`
  - Look for Java (`rO0AB` base64 or hex `ACED0005`), Python pickle (`gASV`/`gAWV`), PHP (`O:<n>:"`, `a:<n>:{`), .NET (`AAEAAAD/////`, `"$type":`), or `Content-Type: application/x-java-serialized-object`.
  - Report the presence. Do not send gadget payloads.
- **Mass assignment.** Using your own test account on staging:
  - `curl -X PATCH http://localhost:3000/api/users/me -H "Authorization: Bearer $TOKEN_A" -H 'Content-Type: application/json' -d '{"displayName":"t","role":"admin","isAdmin":true,"tenantId":"other","emailVerified":true}'`
  - Then `GET /api/users/me`. Expect 400 (unknown fields rejected), or 200 with the privileged fields unchanged. Repeat on signup and create endpoints.
- **Cookie and state tampering.** Change a client-visible cookie or hidden field (`role=user` to `admin`, `price=100` to `1`), or flip one character of the session cookie. Expect the value to be ignored or recalculated server-side, or the session invalidated (401 or re-login).
- **Webhooks:**
  - `curl -X POST http://localhost:3000/webhooks/stripe -H 'Content-Type: application/json' -d '{"type":"invoice.paid"}'` (no signature) should return 400/401 with no state change.
  - Replaying a captured, validly signed test event outside the tolerance window should also be rejected.
- **SRI and third-party scripts:**
  - `curl -s http://localhost:3000/ | rg -oP '<(script|link)\b[^>]*(src|href)="(https?:)?//[^"]+"[^>]*>' | rg -v 'integrity='`
  - `curl -sI http://localhost:3000/ | rg -i 'content-security-policy'`, and check which script origins are allowed.
- **Artifact and package integrity:** `npm audit signatures`; `cosign verify --certificate-identity-regexp '^https://github.com/<org>/' --certificate-oidc-issuer https://token.actions.githubusercontent.com <image>@sha256:<digest>`; `gh attestation verify oci://<image>@sha256:<digest> --owner <org>`.

### Tools
- **Semgrep:** `semgrep scan --config p/owasp-top-ten --config p/github-actions .`. Useful registry rules (tagged A08:2025):
  - `python.lang.security.deserialization.pickle.avoid-pickle`, `python.lang.security.deserialization.avoid-pyyaml-load`, `python.lang.security.deserialization.avoid-jsonpickle`
  - `java.lang.security.audit.object-deserialization`, `java.lang.security.jackson-unsafe-deserialization`, `java.lang.security.audit.xml-decoder`
  - `php.lang.security.unserialize-use`, `csharp.lang.security.insecure-deserialization.binary-formatter`, `csharp.lang.security.insecure-deserialization.newtonsoft`
  - `csharp.dotnet.security.audit.mass-assignment`, `python.django.security.injection.mass-assignment`
  - `javascript.lang.security.audit.prototype-pollution.*`, `html.security.audit.missing-integrity`, `go.lang.security.deserialization.unsafe-deserialization-interface`
  - `yaml.github-actions.security.pull-request-target-code-checkout`, `yaml.github-actions.security.run-shell-injection`
- **CodeQL** (`security-extended`): `js/functionality-from-untrusted-source` and `js/functionality-from-untrusted-domain` (CWE-830/SRI), `js/unsafe-deserialization`, `py/unsafe-deserialization`, `java/unsafe-deserialization`, `cs/unsafe-deserialization-untrusted-input`, `js/prototype-polluting-assignment`, `js/insecure-download`, `actions/untrusted-checkout/critical`.
- **Bandit:** `bandit -r . -t B301,B302,B403,B506,B614,B615`. B301 covers pickle, dill, shelve, jsonpickle and `pandas.read_pickle`; B302 marshal; B403 import pickle; B506 yaml_load; B614 pytorch_load; B615 huggingface_unsafe_download.
- **Java:** SpotBugs + FindSecBugs patterns `OBJECT_DESERIALIZATION`, `JACKSON_UNSAFE_DESERIALIZATION`, `XML_DECODER`, `ENTITY_MASS_ASSIGNMENT`, `UNSAFE_HASH_EQUALS`.
- **.NET analyzers:** CA2300–CA2302 (BinaryFormatter), CA2326 (TypeNameHandling ≠ None), CA2327–CA2330 (insecure `JsonSerializerSettings`/`JsonSerializer`). Promote them with `dotnet_diagnostic.CA2326.severity = error` in `.editorconfig`.
- **PHP:** `psalm --taint-analysis` (tainted unserialize and eval sinks).
- **CI:** `zizmor .github/workflows` (`dangerous-triggers`, `template-injection`, `cache-poisoning`, `artipacked`, `github-env`, `impostor-commit`, `unpinned-uses`); OpenSSF Scorecard `Dangerous-Workflow`.
- **DAST (passive, safe):** `docker run --rm -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:3000`. Relevant rules: 90003 "Sub Resource Integrity Attribute Missing" and 10017 "Cross-Domain JavaScript Source File Inclusion".
- **Integrity verification:**
  - Generate an SRI hash: `curl -s <url> | openssl dgst -sha384 -binary | openssl base64 -A`
  - `sha256sum -c`, `cosign verify`, `gh attestation verify`, `slsa-verifier verify-artifact`, `npm audit signatures`
  - Secret scanners (gitleaks/trufflehog) for leaked signing keys (`APP_KEY`, `SECRET_KEY`, webhook secrets).

### Fix / remediation
**Deserialization: use data-only formats plus schema validation, and never native object graphs from clients**
```python
# BAD
state = pickle.loads(base64.b64decode(request.cookies["cart"]));  cfg = yaml.load(body, Loader=yaml.Loader)
# GOOD (FastAPI/Pydantic): plain JSON + strict schema; YAML via safe_load
class CartState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[int]
state = CartState.model_validate_json(raw);  cfg = yaml.safe_load(body)
```
```java
// BAD: new ObjectInputStream(req.getInputStream()).readObject();  mapper.activateDefaultTyping(...)
// GOOD: JSON into a concrete record type; if Java serialization is unavoidable, allowlist classes (JEP 290/415)
record OrderDto(long productId, int qty) {}
OrderDto dto = mapper.readValue(body, OrderDto.class);      // no default typing, no @JsonTypeInfo(use=CLASS)
ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("com.acme.dto.*;java.base/*;!*"));
```
.NET: remove BinaryFormatter and its relatives. Use `System.Text.Json` with concrete types, or `TypeNameHandling.None` (the default) plus a custom `ISerializationBinder` if polymorphism is required. PHP: `json_decode`, or `unserialize($s, ['allowed_classes' => false])`. Laravel: `decryptString()` instead of `decrypt()`. Rotate any leaked `APP_KEY`, `SECRET_KEY` or webhook secret, and move it to a secrets manager.

**Mass assignment: an explicit allowlist per action**
```ts
// BAD (Express/Prisma): await prisma.user.update({ where: { id: me }, data: req.body })
const UpdateMe = z.object({ displayName: z.string().max(80), bio: z.string().max(500).optional() }).strict();
await prisma.user.update({ where: { id: me }, data: UpdateMe.parse(req.body) });   // role/isAdmin -> 400
// NestJS: app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
```
```php
// BAD: protected $guarded = [];   User::create($request->all());
protected $fillable = ['name', 'email'];                       // never role/is_admin/tenant_id
User::create($request->validated());                           // FormRequest rules = allowlist
// dev guard: Model::preventSilentlyDiscardingAttributes(! app()->isProduction());
```
```csharp
// BAD: public IActionResult Put([FromBody] User user) { _db.Update(user); ... }
public record UpdateProfileDto(string DisplayName, string? Bio);
public async Task<IActionResult> Put(UpdateProfileDto dto) { var u = await _db.Users.FindAsync(UserId);
  u!.DisplayName = dto.DisplayName; u.Bio = dto.Bio; await _db.SaveChangesAsync(); return NoContent(); }
```
Spring: bind to `record` DTOs, or `@InitBinder` with `binder.setAllowedFields(...)`. Django: explicit `fields = [...]` and DRF `read_only_fields`. Go: request structs separate from GORM models, `json:"-"` on privileged fields, `db.Model(&u).Select("Name","Bio").Updates(dto)`.

**Third-party scripts: pin, add SRI, restrict with CSP (or self-host)**
```html
<!-- BAD --> <script src="https://cdn.example.com/lib@latest/lib.min.js"></script>
<!-- GOOD --> <script src="https://cdn.jsdelivr.net/npm/lib@1.2.3/dist/lib.min.js"
  integrity="sha384-<base64 digest>" crossorigin="anonymous"></script>
<!-- plus CSP: script-src 'self' https://cdn.jsdelivr.net; do not CNAME vendor services under the parent cookie domain -->
```
**Webhooks and callbacks: verify the HMAC over the raw body, compare in constant time, enforce a timestamp window**
```js
app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), (req, res) => {
  let evt; try { evt = stripe.webhooks.constructEvent(req.body, req.get('stripe-signature'), process.env.STRIPE_WHSEC); }
  catch { return res.sendStatus(400); }            // BAD alternative: JSON.parse(req.body) with no signature check
  /* idempotency: ignore evt.id already processed */ res.sendStatus(200); });
```
```python
sig = request.headers.get("X-Hub-Signature-256", "")     # GitHub
expected = "sha256=" + hmac.new(SECRET, request.get_data(), hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, sig): abort(401)    # never ==
```
**Downloads, updates and CI**
```dockerfile
# BAD: RUN curl -fsSL https://get.tool.dev | sh
ADD --checksum=sha256:<sha256> https://github.com/org/tool/releases/download/v1.2.3/tool.tgz /tmp/
```
In GitHub Actions: never combine `pull_request_target` or `workflow_run` with a checkout or build of PR head code. Use `pull_request` with `permissions: contents: read`. Do not restore caches in release jobs. Pass untrusted `${{ github.event.* }}` values through `env:` rather than inlining them into `run:`. Sign release artifacts and verify signatures or attestations before deploying (cosign / `gh attestation verify`). Promote the verified artifact instead of rebuilding it.

### Best-practice checklist
- [ ] No native or polymorphic deserialization of untrusted input. Allowlisted types only, and serializers documented as insecure are never used (ASVS 5.0 **1.5.2**).
- [ ] Every create or update endpoint limits writable fields per action through DTOs or allowlists (`$fillable`, `whitelist:true`, `fields=[...]`, `setAllowedFields`) (**15.3.3**). JS merges are safe from prototype pollution (use `Map`, `Object.create(null)`, reject `__proto__`/`constructor`) (**15.3.6**).
- [ ] Input validation is enforced server-side. Client-side values (price, role, owner) are never trusted (**2.2.2**).
- [ ] External JS, CSS and fonts are only static, versioned URLs with SRI, or there is a documented exception; CSP restricts script origins (**3.6.1**).
- [ ] Self-contained tokens and signed cookies are verified by signature or MAC before use (**9.1.1**). Sessions are verified by a trusted backend (**7.2.1**). Security decisions never rely on unsigned cookies.
- [ ] Inbound webhooks and callbacks: HMAC or signature over the raw body, constant-time compare, timestamp tolerance, idempotency key. Per-message signatures for highly sensitive cross-system requests (**4.1.5**).
- [ ] Signing and encryption keys (`APP_KEY`, `SECRET_KEY`, webhook secrets) are in a secrets manager, rotated, never committed (**13.3.1**), and can be rotated on leak.
- [ ] No `curl | sh`. Downloads are checksum- or signature-verified (`ADD --checksum`, `sha256sum -c`, cosign). Auto-updaters verify signatures.
- [ ] Dependencies come only from trusted or expected registries (**15.2.4**). Lockfile hashes enforced (`npm ci`, `--require-hashes`, `go.sum`).
- [ ] CI: no untrusted code under privileged triggers, least-privilege `GITHUB_TOKEN`, required review for code and pipeline changes, signed builds and provenance, artifacts promoted rather than rebuilt.
- [ ] Deterministic module and binary resolution (absolute paths, no writable plugin directories, no computed `require`/`import` of user input).

### Severity guidance
- **Critical:** pre-auth deserialization of client-controlled data with a native or polymorphic serializer (pickle, `ObjectInputStream`, BinaryFormatter, `TypeNameHandling.All/Auto`, PHP `unserialize`, node-serialize), which means RCE. A leaked signing or encryption key plus a deserializing cookie or session (Laravel `APP_KEY`). A `pull_request_target`/`workflow_run` job that checks out and runs fork code with secrets or a write token. Mass assignment on signup or profile that sets `role`/`isAdmin`/`tenantId` (privilege escalation or cross-tenant access). An unsigned webhook that triggers payments, fulfillment or account changes.
- **High:** deserialization reachable only after authentication, or from a shared queue or cache fed by lower-trust services. Mass assignment of ownership, price or status fields. Role, price or user ID taken from an unsigned cookie or hidden field. Third-party script from an untrusted, abandoned or expired domain on authenticated pages (CWE-830; compare polyfill.io, 2024). An auto-updater or plugin loader without signature verification. A vendor CNAME under the parent domain that receives auth cookies.
- **Medium:** SRI missing on a script from a reputable, versioned CDN. `curl | sh` or unverified download in CI for build tooling. Prototype-pollution sink without a demonstrated gadget. Webhook signature checked but with no replay protection or a non-constant-time compare. `yaml.load` with FullLoader on admin-only input.
- **Low:** SRI missing on fonts or CSS only. Theoretical search-path issues in developer-only scripts. Client-side hidden values that the server already recomputes (defense in depth).

### Sources
- https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/ and https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A08_2025-Software_or_Data_Integrity_Failures.md
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/0x00_2025-Introduction.md, https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A04_2025-Cryptographic_Failures.md (CWE-347 mapping)
- ASVS 5.0.0: https://raw.githubusercontent.com/OWASP/ASVS/master/5.0/en/0x10-V1-Encoding-and-Sanitization.md, .../0x12-V3-Web-Frontend-Security.md, .../0x24-V15-Secure-Coding-and-Architecture.md, .../0x18-V9-Self-contained-Tokens.md, .../0x16-V7-Session-Management.md, .../0x13-V4-API-and-Web-Service.md, .../0x22-V13-Configuration.md, .../0x11-V2-Validation-and-Business-Logic.md
- https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html, https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html, https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html, https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html, https://cheatsheetseries.owasp.org/cheatsheets/Software_Supply_Chain_Security_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/915.html (CWE 4.20; ParentOf CWE-1321), https://cwe.mitre.org/data/definitions/502.html, /829.html, /830.html, /494.html, /345.html, /565.html, /784.html
- https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide, https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2326
- https://bandit.readthedocs.io/en/latest/plugins/index.html, https://bandit.readthedocs.io/en/latest/blacklists/blacklist_calls.html, https://find-sec-bugs.github.io/bugs.htm, https://www.zaproxy.org/docs/alerts/90003/
- Semgrep rules (verified files and tags): https://github.com/semgrep/semgrep-rules (python/lang/security/deserialization/pickle.yaml, html/security/audit/missing-integrity.yaml, csharp/dotnet/security/audit/mass-assignment.yaml, yaml/github-actions/security/pull-request-target-code-checkout.yaml, php/lang/security/unserialize-use.yaml, go/lang/security/deserialization/unsafe-deserialization-interface.yaml)
- CodeQL query IDs: https://github.com/github/codeql (javascript/ql/src/Security/CWE-830, CWE-502, CWE-915, CWE-829; python/ql/src/Security/CWE-502; java/ql/src/Security/CWE/CWE-502; csharp/ql/src/Security Features/CWE-502; actions/ql/src/Security/CWE-829)
- https://docs.zizmor.sh/audits/, https://docs.github.com/en/actions/reference/security/secure-use
- https://blog.gitguardian.com/exploiting-public-app_key-leaks/, https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://orca.security/resources/blog/tanstack-npm-supply-chain-worm/ (cache poisoning plus valid provenance), https://thehackernews.com/2025/10/self-spreading-glassworm-infects-vs.html, https://about.codecov.io/security-update (Codecov bash uploader, CWE-494)
