# Quick checklist — OWASP Top 10:2025 + API Security Top 10:2023

This is the compact pass for small repos and for triage. Each bullet is something to look for in code or config.
When you confirm a finding, open that category's detailed reference (`web/Axx-*.md` or `api/APIx-*.md`) for the
framework-specific fix, ASVS 5.0 IDs and severity anchors. Filing rules are in `category-map.md`.

## A01 Broken Access Control (+ API1 BOLA, API3 read side, API5 BFLA, API7 SSRF)
- Handlers that load by an ID from the request (`findById(req.params.id)`, `get(Model, id)`, `WHERE id = ?`) with no owner or tenant condition. → API1
- Routes mounted before the auth middleware, or outside it. Check the order of `app.use`, router registration and decorators. Missing `Depends(current_user)` / `@PreAuthorize` / `[Authorize]`.
- Admin or privileged routes that need a login but check no role. Roles checked only in the UI. → API5
- Responses that serialize whole rows (`SELECT *`, `res.json(user)`, `model_dump()`) and leak `password_hash`, tokens, internal flags or other users' PII. → API3
- Outbound fetch of a user-supplied URL (`fetch(req.body.url)`, `requests.get(url)`, `http.Get(u)`, wkhtmltopdf/puppeteer on user URLs) with no allowlist and no private-IP block. → SSRF, API7 (filed under A01:2025)
- File paths built from input (`path.join(base, req.query.f)`, `open(f"uploads/{name}")`) without normalize-and-contain. → path traversal
- Cookie-auth state-changing routes with no CSRF token and no SameSite/Origin check. JWTs in Authorization headers are not CSRF-prone.
- Open redirects (`res.redirect(req.query.next)`). Directory listing enabled.

## A02 Security Misconfiguration (+ API8, API9)
- Debug mode in shipped config: `DEBUG=True`, `FastAPI(debug=True)`, `app.run(debug=True)`, Spring devtools/actuator exposed, `NODE_ENV` not production.
- CORS: reflects any origin with credentials (`origin: true` + `credentials: true`, `allow_origins=["*"]` + `allow_credentials=True`), or `*` on private data.
- No security headers: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors`. No `helmet`/equivalent. `X-Powered-By` or `Server` leaks.
- Cookies without `Secure` / `HttpOnly` / `SameSite`.
- XML parsers with external entities enabled (XXE).
- Dockerfile: runs as root, EOL base image, `COPY . .` with no `.dockerignore` (ships `.env`/`.git`), secrets in `ENV`/`ARG`.
- Old or undocumented routes still mounted (`/v1`, `/legacy`, `/debug`, `/internal`), and Swagger/GraphiQL exposed in prod. → API9

## A03 Software Supply Chain Failures
- Known-vulnerable or EOL dependencies (scanner output; check reachability). Runtime EOL (Node 14/16, Python 3.8, etc.).
- No lockfile, unpinned ranges for critical libs, `requirements.txt` without pins or hashes, `npm install` instead of `npm ci` in CI/Docker.
- GitHub Actions pinned by tag, not commit SHA. `curl | bash` installers. Install scripts allowed in CI.
- Unused dependencies. No SBOM or dependency scanning in CI.

## A04 Cryptographic Failures (+ API2 JWT/hash side)
- Password hashing with MD5/SHA-1/SHA-256, unsalted or fast. Should be argon2id, bcrypt or scrypt, with the cheat-sheet parameters.
- JWT not verified: `jwt.decode()` used for auth, `verify_signature: False`, `algorithms` including `none`, or not pinned. Weak or hard-coded HS256 secret.
- Tokens, IDs or reset codes from `Math.random()` / `random` / `rand()`. Should come from a CSPRNG.
- TLS verification disabled (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`). HTTP to internal services carrying secrets.
- ECB mode, static IVs, home-made crypto, hard-coded encryption keys (CWE-321).

## A05 Injection
- SQL built by string concatenation or interpolation (template literals, f-strings, `%`/`.format`, `Sprintf`, `+`), including in `LIMIT`/`ORDER BY`. ORM raw methods fed interpolated strings.
- NoSQL filters taken straight from the body (a Mongo filter object where a string is expected).
- Shell calls with user data: `exec(\`...${x}\`)`, `subprocess.*(..., shell=True)` with f-strings, `os.system`, `Runtime.exec(String)`, PHP `system`/backticks.
- XSS sinks: `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `|safe`, `{!! !!}`, `Html.Raw`. HTML built by string concatenation (including HTML fed to PDF renderers).
- Template or code evaluation of user input: `render_template_string(user)`, `eval`, `new Function`, SpEL/OGNL.
- LLM output flowing into SQL, shell, HTML or URLs. Untrusted text concatenated into system prompts.

## A06 Insecure Design (+ API4, API6)
- The server trusts client-sent price, total, discount, role, quantity or status. Negative or zero quantities accepted.
- Multi-step flows (checkout, reset, approval) with no server-side state check. Race conditions on balances, coupons or stock (read-then-write without a transaction or lock).
- Unbounded list endpoints: `limit`/`page_size` uncapped or defaulting huge. No body size, upload size or timeout limits. Costly third-party calls (SMS, email, LLM) without per-user quotas. → API4
- Sensitive flows (signup, checkout, referral, OTP) with no anti-automation or rate limit. → API6
- Unrestricted file upload (type, size, storage location, served from the same origin). Plaintext storage of passwords or sensitive data (CWE-256/312 sit here in 2025).

## A07 Authentication Failures (+ API2)
- Hard-coded credentials or secrets in code, config fallbacks (`process.env.X || 'secret'`), committed `.env`, default admin accounts.
- No rate limiting or lockout on login, OTP, reset or registration. User enumeration (different errors or status codes for unknown user vs wrong password).
- JWT/session issues: `exp` missing or very long, `aud`/`iss` not checked, no revocation on logout or password change, session ID not rotated after login (fixation).
- Weak password policy (no minimum length ≥ 8, no breached-password check), insecure reset tokens (guessable, no expiry, not single-use).
- Endpoints that should need authentication but don't (CWE-306). OAuth without `state`/PKCE, or loose `redirect_uri` matching.

## A08 Software or Data Integrity Failures (+ API3 write side, API10)
- Mass assignment: whole `req.body` / `**payload` / `model.update(request.data)` / `_.merge(entity, req.body)` reaching the DB, so a caller can set `role`, `isAdmin`, `ownerId`, `price` or `plan`. → API3
- Insecure deserialization: `pickle.loads`, `yaml.load` without SafeLoader, Java `ObjectInputStream`, PHP `unserialize`, `node-serialize` on untrusted data.
- Webhooks accepted without a signature or HMAC check (payment, billing, Git events). → API10
- CDN `<script>` without `integrity` (SRI). Downloads or auto-updates run without checksum or signature checks.
- Security decisions based on unsigned cookies or client-side state.

## A09 Security Logging & Alerting Failures
- Secrets, passwords, tokens or full PII in logs (`console.log(req.body)`, `log.info(f"...{password}")`).
- Login failures, access-control denials, validation failures and admin actions not logged. No correlation or request IDs.
- Log injection: user input logged raw into line-based logs (CR/LF).
- No alerting path. This is usually outside the repo, so mark it ⚠️ and ask.

## A10 Mishandling of Exceptional Conditions
- Fail-open: `catch` blocks that call `next()`, return success or skip checks. Auth or authorization that passes when a dependency errors.
- Swallowed errors (`except: pass`, empty `catch {}`, `_ = err` in Go), and handlers that return `ok: true` after a failure.
- Exception text or stack traces sent to clients (`err.stack`, `str(exc)`, `traceback.format_exc()`, `e.getMessage()` in responses). No global error handler.
- Unhandled promise rejections in Express 4 async handlers. Missing timeouts on outbound calls. Partial writes with no transaction or rollback. Resources not released on error.

## API-only extras
- API9 inventory: routes in code vs the OpenAPI spec; versions still served; staging/debug hosts; undocumented internal endpoints.
- API10 third-party consumption: responses from external APIs used without schema validation, redirects followed blindly, no timeouts, and third-party data passed to SQL/HTML/shell.
- GraphQL: introspection enabled in prod, no depth or complexity limits, batching/aliases that bypass rate limits, resolvers that skip object-level checks.
