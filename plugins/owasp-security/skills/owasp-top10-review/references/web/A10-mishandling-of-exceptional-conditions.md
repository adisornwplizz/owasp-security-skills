## A10:2025 – Mishandling of Exceptional Conditions
**Edition notes:** A new category in 2025. It is one of the two new entries; SSRF, the old A10:2021, was folded into A01:2025. It maps 24 CWEs covering improper error handling, logic errors, failing open and other abnormal-condition scenarios: max incidence 20.67%, avg 2.95%, 769,581 occurrences, 3,416 CVEs. OWASP says these CWEs previously sat under "poor code quality" or were scattered. For example, CWE-209 was mapped in A04:2021 Insecure Design, and CWE-756 in A05:2021 Security Misconfiguration. The official reference is ASVS 5.0 V16.5 Error Handling. ASVS 2.3.3 (transactions) and 13.4.2 (debug modes off) are also relevant. There is heavy overlap with A01/A07 (fail-open auth), A02 (debug config) and A09 (errors must be logged and alerted on).

### What it is (issue)
The program fails to prevent, detect or correctly respond to abnormal situations: bad or missing input, dependency or network failures, resource exhaustion, nulls, or partial failures in multi-step operations. It then crashes, leaks internals, or continues in an undefined or less-secure state. The security-critical form is **failing open**: an exception or error path in authN, authZ, validation or payment logic ends with access granted or a transaction half-committed. Other forms are swallowed errors that hide attacks, stack traces or SQL errors returned to clients (reconnaissance for injection), and uncaught exceptions or unhandled promise rejections that crash the process (DoS).

### Root causes
- Happy-path design with no failure-mode analysis (dependency down, timeout, malformed input, partial write, concurrent retry).
- **Permissive defaults**: `allowed = true`, or a function that only returns deny on the success path, so any exception falls through to "allow". Error branches that log but don't `return`.
- Catch blocks written to "make the error go away" (`catch {}`, `except: pass`, `.catch(() => {})`, `_ = err`), or catching at the wrong layer, so the caller cannot react.
- Language and framework semantics developers forget. Go errors are values and are easy to ignore. JS promises reject silently unless awaited, and Node ≥15 turns an unhandled rejection into a process crash (default `--unhandled-rejections=throw`). Express 4 does not catch async handler errors (Express 5 does). `NaN` comparisons are always false. PHP returns `false`/`null` instead of throwing (`json_decode`; `strpos` returns 0 vs `false`). Spring `@Transactional` rolls back only on unchecked exceptions by default. `net/http` recovers panics only in the handler goroutine.
- Error responses built from exception objects for convenience (`err.message`, `str(e)`, `ex.ToString()`). Debug mode or dev error pages left enabled.
- Multi-step state changes without a transaction, idempotency key or compensating action.
- No resource-cleanup discipline (`finally`/`with`/`defer`/`using`), no resource limits, timeouts or circuit breakers.
- No central error-handling policy, so behaviour differs per team or module.

### Key CWEs
(Official A10:2025 mapping: 24 CWEs. ★ = most relevant for web/API devs.)
- ★ CWE-636 Not Failing Securely ('Failing Open')
- ★ CWE-209 Generation of Error Message Containing Sensitive Information
- ★ CWE-248 Uncaught Exception
- ★ CWE-252 Unchecked Return Value
- ★ CWE-390 Detection of Error Condition Without Action
- ★ CWE-755 Improper Handling of Exceptional Conditions
- ★ CWE-460 Improper Cleanup on Thrown Exception
- ★ CWE-476 NULL Pointer Dereference
- Others: CWE-215 Insertion of Sensitive Information Into Debugging Code · CWE-234 Failure to Handle Missing Parameter · CWE-235 Improper Handling of Extra Parameters · CWE-274 Improper Handling of Insufficient Privileges · CWE-280 Improper Handling of Insufficient Permissions or Privileges · CWE-369 Divide By Zero · CWE-391 Unchecked Error Condition · CWE-394 Unexpected Status Code or Return Value · CWE-396 Declaration of Catch for Generic Exception · CWE-397 Declaration of Throws for Generic Exception · CWE-478 Missing Default Case in Multiple Condition Expression · CWE-484 Omitted Break Statement in Switch · CWE-550 Server-generated Error Message Containing Sensitive Information · CWE-703 Improper Check or Handling of Exceptional Conditions · CWE-754 Improper Check for Unusual or Exceptional Conditions · CWE-756 Missing Custom Error Page

### How to detect — code review
**Stack-agnostic signals.** Start with security code: auth and JWT/session middleware, authz guards or policies, validators, CSRF and webhook-signature checks, rate limiters, payment and transfer services, and the global error handler.
- **Fail-open**: for every `catch`/`except`/`if err != nil` in that code, does it *deny* (401/403/abort/rethrow) or *continue*? Also look for an error response that is not followed by `return`.
  - Permissive defaults: `rg -n -i '\b(allowed|authori[sz]ed|permitted|hasAccess|isAdmin|isValid|verified|granted)\s*[:=]\s*true\b'`
  - Catch returns allow: `rg -n -U 'except[^:\n]*:\s*\n\s*(pass|continue|return\s+True)\b'`, `rg -n -U 'catch\s*(\([^)]*\))?\s*\{[^}]*return\s+true'`
- **Swallowed errors**: `rg -n -U 'catch\s*(\([^)]*\))?\s*\{\s*\}'` (JS/Java/C#/PHP), `rg -n '\.catch\(\s*\(\s*\w*\s*\)\s*=>\s*(\{\s*\}|null|undefined)\s*\)'`, `rg -n -U 'if err != nil \{\s*\}'`. Also look for catch blocks that only log and then fall through to success.
- **Unchecked returns / errors**: `rg -n '(^\s*_\s*=\s*\w|,\s*_\s*:?=\s*\w)'` (Go). Pay particular attention to password compare, JWT parse or verify, signature verify, `json.Unmarshal`/`strconv.*` (a zero value becomes user id 0), `Close()` on writers, `rows.Err()`, `tx.Commit()`.
- **Internals leaked to clients**: exception message or stack in the response body; debug flags; framework error-page config (see per-stack patterns below).
- **No last-resort handler**: missing Express 4-arity error middleware, `@RestControllerAdvice`, `UseExceptionHandler`, `@app.exception_handler(Exception)`, recover middleware. Also check background workers, queues and cron jobs, which are often unguarded.
- **Partial state**: multi-step writes (debit→credit→ledger, reserve→charge→ship) outside one transaction; catch blocks *inside* a transaction; manual `begin` with no rollback on error paths; no idempotency key on retryable POSTs.
- **Cleanup**: resources acquired without `finally`/`with`/`defer`/`using`/try-with-resources (files, DB connections, locks, temp uploads); Node `.pipe()` instead of `stream.pipeline()`.
- **Switches / parameters / arithmetic**:
  - `switch` on role, status or enum without `default`/exhaustiveness; unintended fall-through.
  - Handlers that assume a parameter exists or is a scalar (`req.query.x.toLowerCase()` breaks on `?x=1&x=2`).
  - Division by user-derived counts (Go integer `/0` panics).
  - `Number(...)`/`parseInt(...)` of input without `Number.isFinite`: `NaN > limit` is false, so the check is bypassed.

**Per-stack high-signal patterns**
- **Node (Express/NestJS/Next.js)**
  - Express 4 (`"express": "^4` in package.json) with `async (req, res` handlers and no `express-async-errors`/wrapper. A rejection becomes an unhandled rejection and, on Node ≥15, a process crash. Express 5 forwards rejected promises to `next(err)`.
  - Auth middleware `catch` that calls `next()` without the error (see the Semgrep rule below).
  - Leaks: `rg -n 'res\.(status\(\d+\)\.)?(send|json|end)\((\s*(err|error|e)\s*\)|[^)]*\b(err|error|e)\.(stack|message))'`
  - Global handler missing: no `app.use((err, req, res, next) =>`. `process.on('uncaughtException'` handlers that don't exit.
  - Safe defaults to confirm rather than flag: the Express default handler omits the stack when `NODE_ENV=production`; NestJS returns `{"statusCode":500,"message":"Internal server error"}` for unknown errors; Next.js replaces Server Component error messages with a generic message and `digest` in production. Custom filters or route handlers that return `exception.message`/`String(err)` undo these.
- **Python (Django/FastAPI/Flask)**
  - Debug: `rg -n 'DEBUG\s*=\s*(True|.*get\([^)]*,\s*True\))|debug\s*=\s*True'` (Django `DEBUG`, `app.run(debug=True)` gives the Werkzeug interactive debugger, `FastAPI(debug=True)`). An env lookup that *defaults* to True is a classic.
  - Leaks: `rg -n 'str\((e|exc|err|ex)\)|traceback\.(format_exc|print_exc)\('` inside `return`/`JsonResponse`/`HTTPException(detail=...)`.
  - `except Exception:`/bare `except:` inside `with transaction.atomic():`. Django warns: "Avoid catching exceptions inside atomic!"
- **Java (Spring Boot)**
  - `rg -n 'server\.error\.include-(stacktrace|message|exception|binding-errors)\s*[:=]\s*(always|on[-_]param|true)'`. Defaults are `never`/`false`. `on-param` lets any client add `?trace=true`. spring-boot-devtools sets these to `always` locally, so make sure devtools is not in the prod artifact.
  - Empty or generic catch: `catch\s*\(\s*(final\s+)?(Exception|Throwable|RuntimeException)\s+\w+\s*\)\s*\{\s*\}`; `\.printStackTrace\(\)`.
  - `@Transactional` methods that throw checked exceptions without `rollbackFor`, or that catch-and-log without rethrowing (both commit partial work). Self-invocation of `@Transactional` methods bypasses the proxy.
  - `ResponseEntity` or `ProblemDetail` built from `e.getMessage()` for non-domain exceptions.
- **Go**
  - `http.Error(...)` not followed by `return`, so the handler keeps executing. `if err != nil { log.Print(err) }` with no return.
  - `bcrypt.CompareHashAndPassword(...)` or `jwt.Parse(...)` results ignored or assigned to `_`; `token.Valid` never checked.
  - Leaks: `rg -n 'http\.Error\(\s*\w+\s*,\s*err\.Error\(\)'`, `gin.H{"error": err.Error()}`.
  - `go func()` inside handlers without `recover` (a panic kills the whole server). `db.Begin/BeginTx` without `defer tx.Rollback()`.
- **PHP (Laravel)**
  - `rg -n -i 'APP_DEBUG\s*=\s*true'` in deployed env files; `display_errors\s*=\s*(On|1)`. Debug mode exposes config; old Ignition versions also had an RCE (CVE-2021-3129).
  - `catch\s*\(\s*\\?(Exception|Throwable)\s+\$\w+\s*\)\s*\{\s*\}`; `->getMessage\(\)|->getTraceAsString\(\)` echoed or returned in JSON.
  - `if\s*\(\s*!?\s*strpos\(` (a match at position 0 is falsy). `json_decode(` without `JSON_THROW_ON_ERROR` returns null. `@func()` error suppression.
  - `DB::beginTransaction()` without `DB::rollBack()` in catch. Prefer `DB::transaction(fn () => ...)`.
- **.NET (ASP.NET Core)**
  - `UseDeveloperExceptionPage\(` outside an `IsDevelopment()` guard; web.config `customErrors mode="Off"` / `<compilation debug="true"`.
  - `IExceptionHandler` registered but `app.UseExceptionHandler()` never called: the docs say the handlers are then *never invoked*.
  - `async\s+void\s+\w+\(` (non-event handler), where an exception crashes the process. Un-awaited tasks (CS4014).
  - `(ex|e|exception)\.(Message|StackTrace|ToString\(\))` in `return Ok/BadRequest/StatusCode/Problem(...)`. `catch (Exception) { return true; }`.

**False-positive notes**
- A catch-all in the **global handler**, a worker loop or a message consumer, which logs, returns a generic 500 or nacks the message, and keeps the process alive, is correct. CWE-396 "generic catch" is intended there.
- An empty catch around best-effort, non-security work (closing a socket, deleting a temp or cache file, telemetry) is acceptable if commented.
- A deliberate fail-open for **availability** of a non-security feature (feature-flag service, cache, sometimes a rate limiter) can be a documented risk decision. Flag it only if it is undocumented or not alerted on. It is never acceptable for authN/authZ.
- Go conventions: `defer f.Close()` on read-only handles and `fmt.Fprintf(w, …)` or `w.Write` results unchecked are fine. `http.Error` with `return` on the next line is fine.
- `err.message` in a **4xx** response for your own domain or validation exceptions (designed to be user-facing) is fine. The issue is 5xx, DB, driver or runtime errors.
- `DEBUG=True` in `settings/dev.py`, test configs or `.env.example` is fine. Verify which settings module or env production actually loads.

### How to detect — runtime (safe, own app only)
Grep every response for leak markers with `rg -e`:
`Traceback \(most recent call last\)|at [\w$.]+\(\w+\.java:\d+\)|Whitelabel Error Page|System\.\w+Exception|goroutine \d+ \[|panic:|SQLSTATE\[|ORA-\d{5}|psycopg2?\.|SequelizeDatabaseError|PrismaClient\w*Error|node_modules/|Werkzeug Debugger|Ignition|/var/www/|/home/\w+/`
1. **Malformed body**: `curl -si -X POST localhost:3000/api/items -H 'Content-Type: application/json' -d '{"name":'`. Expect 400, a generic body (ideally `application/problem+json`) and no markers.
2. **Missing, extra or odd parameters** (CWE-234/235/369): `?page=abc`, `?page=1&page=2`, `?page[]=1`, `{"qty":"abc"}`, `{"qty":null}`, `{"qty":[]}`, `{"qty":0}` on endpoints that divide, a missing required field, an unknown extra field. Expect 4xx, never 500, no partial side effects.
3. **Transport edge cases**: wrong `Content-Type`, empty body, a body over the configured limit (expect 413), unknown route (custom 404), wrong method (405). Also check the `X-Powered-By`/`Server` headers.
4. **Malformed credentials**: `Authorization: Bearer abc`, `Bearer a.b.c`, an expired token, a token signed with a locally generated wrong key, `Authorization: Basic !!!`. Expect 401 every time, never 200 and never 500.
5. **Fail-closed on dependency loss** (local docker-compose only): `docker compose stop redis` (or the auth/policy service or DB). Then call a protected endpoint with and without a valid token. Expect 401/403/503, never 200 with data. Restart the dependency afterwards.
6. **Process resilience**: after steps 1–5, `curl -s localhost:3000/health` still returns 200. The logs show handled errors with request IDs, and no crash, restart or `unhandledRejection` entries.
7. **Spring**: `curl -s 'localhost:8080/nope?trace=true&message=true'`. The body must not contain `trace` or `message` details.
8. **Atomicity**: an integration test that injects a failure between steps (e.g. a mocked gateway timeout after the debit). Assert no debit without a matching credit, and that a retry with the same `Idempotency-Key` has a single effect.
9. **DAST**: a ZAP baseline scan with passive alerts 90022 (Application Error Disclosure) and 10023 (Information Disclosure – Debug Error Messages).

### Tools
- **Semgrep**: `semgrep scan --config p/default --config p/owasp-top-ten`. Registry rules for debug and leak cases (use as `--config r/<id>`): `python.flask.security.audit.debug-enabled.debug-enabled`, `python.django.security.audit.templates.debug-template-tag.debug-template-tag`, `php.laravel.security.laravel-active-debug-code.laravel-active-debug-code`, `csharp.lang.security.stacktrace-disclosure.stacktrace-disclosure`, `csharp.dotnet.security.net-webconfig-debug.net-webconfig-debug`, `go.lang.security.audit.net.pprof.pprof-debug-exposure`. Community coverage of fail-open and swallowed errors is thin, so ship custom rules. These were tested with semgrep 1.178:
```yaml
rules:
- id: catch-continues-with-next            # Express/Nest-style middleware fail-open
  languages: [javascript, typescript]
  severity: ERROR
  message: catch calls next() without the error; request proceeds (fail-open)
  pattern-either:
    - pattern: try { ... } catch ($E) { ... next(); }
    - pattern: try { ... } catch { ... next(); }
    - pattern: try { ... } catch ($E) { ... return next(); }
    - pattern: try { ... } catch { ... return next(); }
- id: go-http-error-without-return
  languages: [go]
  severity: WARNING
  message: http.Error not followed by return; handler keeps executing
  patterns:
    - pattern: "if $C {\n  ...\n  http.Error(...)\n}"
    - pattern-not: "if $C {\n  ...\n  http.Error(...)\n  ...\n  return ...\n}"
- id: go-bcrypt-result-discarded
  languages: [go]
  severity: ERROR
  message: bcrypt comparison result discarded (auth bypass)
  pattern: _ = bcrypt.CompareHashAndPassword(...)
```
- **CodeQL** (`codeql/<lang>-queries:codeql-suites/<lang>-security-and-quality.qls`; many of these are quality queries):
  - JS: `js/stack-trace-exposure`, `js/server-crash`
  - Python: `py/stack-trace-exposure`, `py/flask-debug`, `py/empty-except`, `py/catch-base-exception`, `py/ignored-return-value`
  - Java: `java/stack-trace-exposure`, `java/error-message-exposure`, `java/overly-general-catch`, `java/discarded-exception`, `java/ignored-error-status-of-call`, `java/return-value-ignored`, `java/missing-default-in-switch`, `java/switch-fall-through`, `java/dereferenced-value-may-be-null`, `java/database-resource-leak`
  - Go: `go/missing-error-check`, `go/unhandled-writable-file-close`, `go/stack-trace-exposure`
  - C#: `cs/web/missing-global-error-handler`, `cs/web/debug-binary`, `cs/information-exposure-through-exception`, `cs/empty-catch-block`, `cs/catch-of-all-exceptions`, `cs/unchecked-return-value`
- **JS/TS**: ESLint `no-empty`, `default-case`, `no-fallthrough`; typescript-eslint `no-floating-promises`, `no-misused-promises`, `switch-exhaustiveness-check`; `promise/catch-or-return`; `n/handle-callback-err`.
- **Python**: Bandit `B110 try_except_pass`, `B112 try_except_continue`, `B201 flask_debug_true` (`bandit -r .`); Ruff `E722`, `BLE001`, `S110`, `S112`, `S201` (`ruff check --select E722,BLE001,S110,S112,S201 .`).
- **Go**: `golangci-lint run` (errcheck is on by default; also enable `nilerr`, `exhaustive`, `bodyclose`, `rowserrcheck`, `sqlclosecheck`, `gosec`). `gosec ./...` (G104: errors not checked). `nilaway ./...` for nil panics.
- **Java**: SpotBugs `DE_MIGHT_IGNORE`, `RV_RETURN_VALUE_IGNORED`, `SF_SWITCH_NO_DEFAULT`, `SF_SWITCH_FALLTHROUGH`, `REC_CATCH_EXCEPTION`; FindSecBugs `INFORMATION_EXPOSURE_THROUGH_AN_ERROR_MESSAGE`; Error Prone `FutureReturnValueIgnored`, `CheckReturnValue`, `MissingCasesInEnumSwitch`, `FallThrough`, `CatchAndPrintStackTrace`; PMD `EmptyCatchBlock`.
- **.NET**: analyzers `CA1031` (general catch), `CA1806` (ignored results), `CS4014` (un-awaited task), `CS8509` (non-exhaustive switch expression), `VSTHRD100` (async void), `VSTHRD110` (unobserved async result). Enable `<Nullable>enable</Nullable>` for CWE-476.
- **PHP**: PHPStan or Larastan at high levels (flags `string|false` misuse and unchecked `null`).
- **DAST**: `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:3000`.

### Fix / remediation
- **Deny by default.** Security decisions start as deny and are set to allow only after an explicit successful check. Every error path in a security control returns or throws a denial. Never `next()` or `continue` on error.
- **Catch where you can act, and only what you expect** (specific exception types). Otherwise let the error propagate to one **global last-resort handler** that logs full details with a request ID (A09) and returns a generic RFC 9457/7807 problem response. Background jobs, consumers and goroutines each need their own handler.
- Production config: Django `DEBUG=False`, Flask/FastAPI debug off, `APP_DEBUG=false`, Spring `server.error.include-*=never`, `NODE_ENV=production`, ASP.NET Core dev page only in Development. Also use PHP 8.2 `#[\SensitiveParameter]` and Django `sensitive_variables` so secrets stay out of traces.
- **Atomic business operations** (ASVS 2.3.3): one DB transaction per business operation, catch *outside* the transaction, idempotency keys on retryable writes, and sagas or compensation across services. Spring: `rollbackFor = Exception.class`, or wrap checked exceptions.
- Always clean up (`finally`/`with`/`defer`/`using`/try-with-resources, `stream.pipeline`). Add timeouts, body-size limits, quotas and circuit breakers (ASVS 16.5.2, 15.2.2).
- Validate type and shape at the edge (schema validation). Use strict comparisons (ASVS 15.3.5). Make switches exhaustive (TS `never`, Java switch expressions, `exhaustive` lint, CS8509). Treat Go error returns as mandatory.
- Use error statistics and alerts (e.g. a 5xx rate threshold) rather than per-error noise.

**Node (Express)**
```js
// BAD: any verify error lets the request through; async errors unhandled in Express 4
function auth(req, res, next) { try { req.user = jwt.verify(tok(req), KEY); } catch (e) { console.warn(e); } next(); }
// GOOD
function auth(req, res, next) {
  try { req.user = jwt.verify(tok(req), KEY, { algorithms: ['HS256'] }); }
  catch { req.log.warn({ event: 'authn_token_invalid' }); return res.status(401).json({ title: 'Unauthorized' }); }
  return next();
}
app.use((err, req, res, next) => {             // registered last
  req.log.error({ err }, 'unhandled_error');
  if (res.headersSent) return next(err);
  res.status(500).type('application/problem+json').json({ title: 'Internal Server Error', status: 500, traceId: req.id });
});
```
**Python (Django / FastAPI)**
```python
# BAD: fails open, and the swallowed error commits a half transfer
def can_view(user, doc):
    try: return pdp.check(user, doc)
    except Exception: return True
with transaction.atomic():
    debit(a)
    try: credit(b)
    except Exception: log.exception("credit failed")
# GOOD
def can_view(user, doc) -> bool:
    try: return pdp.check(user, doc) is True
    except Exception: log.exception("authz_pdp_unavailable"); return False
try:
    with transaction.atomic(): debit(a); credit(b)
except DatabaseError: log.exception("transfer_failed"); raise TransferFailed()
@app.exception_handler(Exception)                          # FastAPI last resort
async def unhandled(request, exc):
    log.exception("unhandled_error", extra={"path": request.url.path})
    return JSONResponse({"title": "Internal Server Error"}, status_code=500)
```
**Go**
```go
// BAD
if !isAdmin(r) { http.Error(w, "forbidden", http.StatusForbidden) }   // falls through
bcrypt.CompareHashAndPassword(u.Hash, []byte(pw))                     // result ignored
// GOOD
if !isAdmin(r) { http.Error(w, "forbidden", http.StatusForbidden); return }
if err := bcrypt.CompareHashAndPassword(u.Hash, []byte(pw)); err != nil { unauthorized(w); return }
tx, err := db.BeginTx(ctx, nil); if err != nil { return err }
defer tx.Rollback()                          // no-op after a successful Commit
if err := debit(ctx, tx, a); err != nil { return err }
if err := credit(ctx, tx, b); err != nil { return err }
return tx.Commit()
```

### Best-practice checklist
- [ ] Unexpected or security-sensitive errors return a generic message. No stack traces, queries, keys, tokens or paths (ASVS 16.5.1).
- [ ] The app keeps operating securely when external resources fail: timeouts, circuit breakers, graceful degradation (16.5.2).
- [ ] The app fails securely when an exception occurs. There are no fail-open paths in authN/authZ/validation/payment, and no transaction is processed despite validation errors (16.5.3).
- [ ] A last-resort handler catches all unhandled exceptions, logs them, and keeps the process alive. This covers workers, consumers, goroutines and Node `unhandledRejection` (16.5.4).
- [ ] Unexpected errors and security-control failures are logged and alerted on (16.3.4; see A09).
- [ ] Business operations are atomic: they succeed completely or roll back. Retries are idempotent (2.3.3).
- [ ] Debug modes, dev error pages and debug endpoints (pprof, actuator) are disabled in production (13.4.2).
- [ ] Resource-demanding functionality has limits (body size, quotas, rate limits) (15.2.2).
- [ ] Types are enforced and comparisons are strict. No type juggling (15.3.5).
- [ ] No empty `catch`/`except`. Catch specific types. Errors are wrapped with context, not swallowed.
- [ ] Every returned error or status is checked (Go `errcheck` clean; `no-floating-promises` clean; CA1806/CS4014 clean).
- [ ] Resources are released on all paths (`finally`/`with`/`defer`/`using`/`pipeline`).
- [ ] Switches on roles, states and enums are exhaustive, with a deny-by-default `default`.

### Severity guidance
- **Critical**: fail-open reachable by an unauthenticated user (an exception or dependency outage leads to access granted, a skipped signature or JWT check, or an ignored password-compare result). A Werkzeug debugger or Laravel debug/Ignition page exposed on a reachable environment (code execution or secret disclosure). Stack traces or errors disclosing secrets, credentials or connection strings.
- **High**: fail-open in authorization for authenticated users. Partial or duplicated financial or inventory transactions from missing rollback or idempotency. An unauthenticated request that crashes the process (unhandled rejection or panic in a goroutine, i.e. remote DoS). Detailed DB errors in responses that enable injection tuning.
- **Medium**: stack traces, framework versions or internal paths in responses (no secrets). `on-param` trace settings. Swallowed exceptions in security-relevant but not bypass-able paths (e.g. audit-log write failures ignored). Resource leaks triggerable by repeated errors. Missing global handler where framework defaults are unsafe.
- **Low**: generic catch clauses that log and rethrow. Missing `default` in non-security switches. Unchecked non-security return values. Verbose but harmless 4xx validation messages. `printStackTrace` to stderr.

### Sources
- https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/ (and https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/)
- https://top10.owasp.org/2025/0x00_2025-Introduction/
- https://owasp.org/Top10/2021/A04_2021-Insecure_Design/ , https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md (plus V2, V13, V15 chapters)
- https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/636.html
- https://expressjs.com/en/guide/error-handling.html
- https://github.com/nodejs/node/blob/main/doc/api/cli.md (`--unhandled-rejections`)
- https://docs.nestjs.com/exception-filters
- https://nextjs.org/docs/app/api-reference/file-conventions/error
- https://docs.djangoproject.com/en/stable/topics/db/transactions/ , https://docs.djangoproject.com/en/stable/howto/error-reporting/
- https://fastapi.tiangolo.com/tutorial/handling-errors/
- https://docs.spring.io/spring-framework/reference/data-access/transaction/declarative/rolling-back.html
- https://github.com/spring-projects/spring-boot (ErrorProperties.java defaults, AbstractErrorController `trace` param, devtools-property-defaults.properties)
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling
- https://laravel.com/docs/12.x/errors
- https://github.com/semgrep/semgrep-rules (rule files cited)
- https://codeql.github.com/codeql-query-help/javascript-cwe/ , …/python-cwe/ , …/java-cwe/ , …/go-cwe/ , …/csharp-cwe/
- https://bandit.readthedocs.io/en/latest/plugins/index.html , https://docs.astral.sh/ruff/rules/blind-except/ , https://docs.astral.sh/ruff/rules/bare-except/
- https://github.com/securego/gosec/blob/master/RULES.md , https://golangci-lint.run/docs/linters/
- https://find-sec-bugs.github.io/bugs.htm
- https://www.zaproxy.org/docs/alerts/
