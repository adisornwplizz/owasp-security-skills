## A09:2025 – Security Logging & Alerting Failures
**Edition notes:** Same #9 slot as 2021, renamed from "Security Logging and Monitoring Failures" to put the emphasis on *alerting*, i.e. logs must lead to action. OWASP puts it on the list through the community survey. It is under-represented in CVE/test data (5 CWEs, avg incidence 3.91%, 723 CVEs). CWE-221 (Information Loss or Omission) joins the 2021 set (117, 223, 532, 778). The page's prevention list now also includes fail-closed rollback, honeytokens, playbooks and NIST SP 800-61r2. NIST has since published 800-61r3 (April 2025), which supersedes r2. ASVS 5.0.0 (May 2025) covers this in V16 "Security Logging and Error Handling". That chapter was V7 in ASVS 4.0.3.

### What it is (issue)
The app records the wrong things, records them badly, or records them and nobody is alerted. It fails to log auditable security events (logins, access-control and validation failures, high-value transactions, admin actions), or logs them without who/what/where/when context. Logs are also mishandled: secrets and PII get written to them, attacker-controlled data gets in un-neutralised (log forging, CWE-117), they are stored only on the host that gets compromised, or they are never turned into timely alerts. In any of these cases a breach goes undetected (OWASP's examples ran for years) and forensics become impossible.

### Root causes
- Logging is treated as a debugging aid, not a security control. There is no documented log inventory or event taxonomy, so each developer logs ad hoc.
- Security decisions are spread across handlers instead of choke points (auth middleware, guards/policies, a global validation handler), so no single place emits the event.
- Log calls are built by string concatenation or interpolation of request data, not structured key/value fields. The result is CRLF injection and unparseable logs.
- Default request loggers and serializers dump whole headers or bodies (pino's default `req` serializer includes all headers, so `authorization` and `cookie` too). ORM or HTTP debug logging (bind params, `EnableSensitiveDataLogging`) is left on in production.
- No correlation ID is propagated, so events cannot be tied to a request, user or session.
- Logs stay on the local disk or in the container and are writable by the app. There is no central, append-only store and no retention policy.
- No alert rules, thresholds, owners or playbooks exist. There is also no heartbeat, so a silent log pipeline goes unnoticed.
- Swallowed exceptions (see A10) leave nothing to log.

### Key CWEs
(Official A09:2025 mapping: 5 CWEs. ★ = most relevant for web/API devs.)
- ★ CWE-778 Insufficient Logging
- ★ CWE-532 Insertion of Sensitive Information into Log File
- ★ CWE-117 Improper Output Neutralization for Logs
- ★ CWE-223 Omission of Security-relevant Information
- ★ CWE-221 Information Loss or Omission
- Related, not in the A09 mapping: CWE-93 CRLF Injection (Semgrep tags log-injection rules with it), CWE-598 (secrets in query strings end up in access logs), CWE-312.

### How to detect — code review
**Stack-agnostic signals (where to look)**
- **Auth flows** (login, logout, MFA, password reset or change, token issue/refresh/revoke, API-key check): every success and failure branch should emit a security event with user id, source IP, request ID and reason. Check the lines just before each `401` or `return false` for a log call.
- **Authorization choke points** (middleware, guards, policies, `@PreAuthorize`, `can()`): each `403` or deny path should be logged (`authz_fail`). Check that role or permission changes and admin actions write an audit record (`authz_change`, `authz_admin`, `user_*`).
- **Global validation and error handlers**: 400/422 should be logged at WARN with field names, not values. Unexpected 5xx should be logged with the stack trace on the server side only.
- **Logger bootstrap/config** (`logger.*`, `logging.*`, `logback*.xml`, `log4j2*.xml`, `appsettings*.json`, `config/logging.php`): check the production level, JSON/structured output, UTC timestamps, the redaction list, and that the sink is stdout or a shipper rather than a local file only.
- **Request-logging middleware**: see which headers and bodies it captures, and on which routes. Auth and payment routes must never log bodies.
- **Sensitive-name heuristic** (case-insensitive, run across the repo):
  `rg -n -i '(log|logger|console|slog|Log|_logger)\.\w+\(.*\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|session_?id|set-cookie|ssn|card_?number|cvv|private_?key)\b'`
- **Log-injection heuristic** (request data concatenated or interpolated into a text log). Regex for `rg -n -e`:
  `(log|logger)\.(info|warn|warning|error|debug)\(.*(\+|\$\{|%s|f["']|\.format\().*(req\.|request\.|params|query|body|headers|getParameter|getHeader|\$_(GET|POST|SERVER))`
- **Logging disabled or suppressed**: `rg -n -i 'logging\.disable|silent:\s*true|level.{0,5}(off|none)|LOG_LEVEL=(error|critical|off)'`
- **Secrets in URLs, which end up in access logs**: `rg -n -i '[?&](token|api_?key|access_token|password|secret)='`
- **IaC**: audit and access logging disabled (CloudTrail, LB/S3 access logs, EKS control-plane logs), `retention_in_days` too short, log buckets public or writable by the app role.
- **Docker/K8s**: logs written only inside the container filesystem, `--log-driver none`, no collector sidecar or DaemonSet.
- **Alerting-as-code**: are there any Prometheus rules, Sentry/Datadog monitors or SIEM detections in the repo or infra repo? If there are none, report "cannot verify alerting from code" and ask.

**Per-stack high-signal patterns**
- **Node (Express/NestJS/Next.js)**
  - `pino(`/`pinoHttp(` with no `redact:` option. The default req serializer logs all headers, so `authorization` and `cookie` are logged. Find with `rg -n 'pino(Http)?\(' ; rg -n 'redact'`.
  - `console\.(log|info|error)\(.*req\.(body|headers)`; morgan custom format containing `:req[authorization]` or `:req[cookie]`.
  - Express error handler `app.use((err, req, res, next)` that sends a response without logging. NestJS `ExceptionFilter`/guards that throw `UnauthorizedException|ForbiddenException` with no logging filter or interceptor.
  - `axios.interceptors` or `fetch` wrappers that log the full config (headers include bearer tokens).
- **Python (Django/FastAPI/Flask)**
  - `logger\.\w+\(f["'].*\{(request|data|payload|password|token)` (f-string, both injection and leak).
  - `logging.*request\.(body|data|POST|META|headers)` and `await request.body()` inside logging middleware.
  - Django: no receiver for `user_login_failed` (`rg -n 'user_login_failed'`), `LOGGING` without a `django.security` logger, `sensitive_post_parameters`/`sensitive_variables` missing on custom credential views.
  - Structlog or python-json-logger absent while a plain `%(message)s` formatter is used. Plain-text formatters do not escape CR/LF.
- **Java (Spring Boot)**
  - `log\.(info|warn|error|debug)\(".*"\s*\+` (concatenation), especially with `getParameter|getHeader`.
  - Logback pattern without `%replace(%msg){'[\r\n]','_'}` or a JSON encoder. Log4j2 pattern without `%enc{%m}{CRLF}`.
  - Missing `@EventListener` for `AbstractAuthenticationFailureEvent`/`AuthorizationDeniedEvent`. Boot auto-configures `DefaultAuthenticationEventPublisher`, but **authorization events are not published unless a `SpringAuthorizationEventPublisher` bean is declared**.
  - Prod profile with `spring.jpa.show-sql=true`, `logging.level.org.hibernate.orm.jdbc.bind=TRACE`, or `logging.level.org.springframework.security=DEBUG|TRACE`.
- **Go**
  - `log\.Printf\(.*%[sv].*(r\.(URL|Header|Form)|password|token)`. The std `log` does not escape newlines. `slog` Text/JSON handlers quote or escape them.
  - `httputil\.DumpRequest(Out)?\([^,]+,\s*true\)` logged (dumps headers and body).
  - Auth middleware that returns 401/403 with no `slog.Warn`/`logger` call.
- **PHP (Laravel)**
  - `Log::\w+\(.*\$request->(all|input|header|getContent)\(`, `logger\(\$request->all\(\)\)`.
  - No listeners for `Illuminate\Auth\Events\Failed` / `Lockout`: `rg -n 'Auth\\Events\\(Failed|Lockout)'`.
  - Prod `.env` with `LOG_LEVEL=debug` or `LOG_CHANNEL=single` (local file only). `withExceptions(...)->dontReport([...])` hiding security exceptions.
- **.NET (ASP.NET Core)**
  - `_logger\.Log\w+\(\$"` (interpolation loses structure; Semgrep `structured-logging`).
  - `EnableSensitiveDataLogging\(\)` / `EnableDetailedErrors\(\)` not wrapped in `IsDevelopment()`.
  - `AddHttpLogging` with `HttpLoggingFields.All` or `RequestBody` on auth routes.
  - .NET 10+: the exception-handler middleware no longer emits logs or metrics for exceptions your `IExceptionHandler` marks handled (`TryHandleAsync` returns true). Your handler must log them itself, or set `SuppressDiagnosticsCallback`.

**False-positive notes**
- Logging the *username or email* on a failed login is expected (needed for brute-force detection). Only the *password or secret value* is the issue. Mask or hash email if your policy treats it as PII.
- String literals such as `"password reset requested"` are fine. Check that the *value* of a sensitive variable is interpolated, not just the word.
- JSON/structured loggers (pino, winston `format.json()`, structlog JSON, slog, Serilog JSON, Logstash/ECS encoders) escape CR/LF. Log-injection hits there are low risk, apart from HTML rendering in log viewers.
- Logging a *hash or prefix* of a token (e.g. first 8 chars of SHA-256) for correlation is acceptable.
- `console.log` in CLI scripts, migrations, tests and seeders is out of scope.
- Verbose or debug logging that is only enabled in dev profiles is fine. Verify the production config actually differs.

### How to detect — runtime (safe, own app only)
Run these against localhost or staging, with test accounts, while tailing the app logs or the log backend.
1. **Canary secret test**: log in with a unique wrong password such as `Canary-PW-7f3a` and call an API with `Authorization: Bearer canary-tok-7f3a`. Then `grep -rF 'canary-' <log dir>` or search the log backend. Expect **zero** hits for the values, but a `authn_login_fail` event with user, IP, UTC timestamp and request ID.
2. **Authz failure logged**: as user A, `curl -H "Authorization: Bearer $A" localhost:3000/api/orders/<B's id>`. Expect 403 plus an `authz_fail` log with user A, the resource and a request ID.
3. **Validation failure logged**: send `{"email":"not-an-email"}`. Expect 400 plus a WARN event naming the field, without echoing large or sensitive values.
4. **Log-injection neutralisation (benign)**: `curl -d 'username=alice%0d%0aINFO fake entry&password=x' localhost:3000/login`. The log must show a single entry with `\r\n` escaped, not a new forged line.
5. **Correlation**: send `-H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'` or `X-Request-ID: test-123`. Check that the ID appears in every log line for that request and in the response header. Also send an over-long or newline-containing request ID; it must be rejected or regenerated.
6. **Admin action audit**: change a test user's role and confirm an immutable audit record (who, what, from→to).
7. **Alert fires**: make N failed logins (e.g. 20 in 1 minute, below your own lockout harm threshold) for a test account. Confirm the alert, metric or notification reaches the on-call channel. Also run a ZAP baseline scan against staging and confirm it is noticed. OWASP counts "security testing tools don't trigger alerts" as a failure.
8. **Pipeline failure**: stop the log shipper or collector in staging. The app must keep running, and a "no logs / monitor disabled" heartbeat alert should fire.
9. **Tamper resistance**: as the app's runtime user, try to delete or modify the log store (e.g. `aws s3 rm` with the app role on a WORM bucket). Expect AccessDenied.

### Tools
- **Semgrep** (`semgrep scan --config <ruleset>`): `p/owasp-top-ten`, `p/secrets`. Specific registry rules:
  - `r/python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure` (CWE-532)
  - `r/java.lang.security.audit.crlf-injection-logs.crlf-injection-logs` (log forging; metadata tags CWE-93)
  - `r/csharp.lang.best-practice.structured-logging.structured-logging`
  - `r/python.lang.security.audit.logging.listeneval.listen-eval` (`logging.config.listen`)
  - Terraform: `terraform.lang.security.eks-insufficient-control-plane-logging…`, `terraform.aws.security.aws-documentdb-auditing-disabled…`, `terraform.gcp.security.gcp-cloud-storage-logging…`
- **CodeQL** (`codeql database analyze db codeql/<lang>-queries:codeql-suites/<lang>-security-extended.qls`):
  - Log injection: `js/log-injection`, `py/log-injection`, `java/log-injection`, `go/log-injection`, `cs/log-forging`
  - Sensitive data in logs: `js/clear-text-logging`, `py/clear-text-logging-sensitive-data`, `java/sensitive-log`, `go/clear-text-logging`
- **SpotBugs + FindSecBugs**: `CRLF_INJECTION_LOGS`.
- **SonarQube** taint rule `S5145` "Logging should not be vulnerable to injection attacks" (Java/C#/Python/PHP/Go; requires the taint-analysis editions).
- **Bandit**: `B612 logging_config_insecure_listen`.
- **Secrets already in logs**: `gitleaks dir ./logs` (gitleaks ≥ 8.19), `trufflehog filesystem ./logs`.
- **IaC**: `trivy config .`, `checkov -d .` (flag disabled audit/access logging and short retention).
- **DAST as an alerting test**: `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example` and confirm your monitoring notices it.

### Fix / remediation
- Emit security events at the choke points (auth middleware, authz guard, global validation handler, admin services), using the OWASP Logging Vocabulary names (`authn_login_fail`, `authz_fail`, `input_validation_fail`, `authz_change`, `sys_monitor_disabled`, …).
- Log structured JSON with `timestamp` (ISO 8601, UTC), `level`, `event`, `user_id`, `src_ip`, `request_id/trace_id`, `method`, `path`, `status`, `app/version`. Propagate W3C `traceparent` (OpenTelemetry). Validate inbound IDs.
- Redact at the logger (allow-list fields; deny-list `authorization`, `cookie`, `set-cookie`, `password`, `token`, `secret`, `card`). Never log request bodies of auth or payment endpoints.
- Neutralise CR/LF in any remaining text layouts (Logback `%replace`, Log4j2 `%enc{…}{CRLF}`, a Python filter).
- Ship logs off-host to an append-only store (WORM or object lock). The app role can write but not delete. Access to logs is itself logged. Retention follows legal/contract needs, e.g. PCI DSS v4.0 10.5.1 requires ≥12 months with the latest 3 months immediately available.
- Alerts with an owner and a playbook. Example starting thresholds to tune against your baseline (not OWASP-mandated):
  - ≥10 failed logins per account in 5 minutes
  - ≥50 failures per IP or across many accounts in 5 minutes (credential stuffing)
  - any `authn_token_reuse`
  - an admin role grant outside a change window
  - a honeytoken touched
  - 5xx rate above 2% for 5 minutes
  - log-silence heartbeat
- Use sampling or aggregation for floods so alerts stay actionable.

**Node (Express + pino)**
```js
// BAD: leaks password, text log, no event on failure
console.log(`login ${req.body.username} pw=${req.body.password}`);
if (!ok) return res.status(401).end();
// GOOD
const logger = pino({ redact: { paths: ['req.headers.authorization','req.headers.cookie','*.password','*.token'], censor: '[REDACTED]' } });
app.use(pinoHttp({ logger, genReqId: (req, res) => {
  const id = /^[\w-]{1,64}$/.test(req.headers['x-request-id'] ?? '') ? req.headers['x-request-id'] : crypto.randomUUID();
  res.setHeader('x-request-id', id); return id; } }));
if (!ok) { req.log.warn({ event: 'authn_login_fail', user: username, ip: req.ip }, 'login failed');
           return res.status(401).json({ error: 'invalid_credentials' }); }
```
**Python (Django + structlog)**
```python
# BAD
logger.info(f"login failed for {username} pw={password}")
# GOOD – JSON renderer escapes CR/LF; Django cleanses 'password' in credentials
structlog.configure(processors=[structlog.processors.TimeStamper(fmt="iso", utc=True),
                                structlog.processors.JSONRenderer()])
log = structlog.get_logger()
@receiver(user_login_failed)
def on_fail(sender, credentials, request, **kw):
    log.warning("authn_login_fail", user=credentials.get("username"),
                ip=request.META.get("REMOTE_ADDR") if request else None)
```
**Java (Spring Boot)**
```java
// BAD: log.info("Failed login for " + request.getParameter("user"));   // CRLF forgery
// GOOD: application.yml -> logging.structured.format.console: ecs   (Boot 3.4+, JSON)
@Bean AuthorizationEventPublisher authzEvents(ApplicationEventPublisher p) {
  return new SpringAuthorizationEventPublisher(p); }          // authz events are off by default
@Component class SecurityEvents {
  @EventListener void fail(AbstractAuthenticationFailureEvent e) {
    log.warn("authn_login_fail user={} reason={}", e.getAuthentication().getName(),
             e.getException().getClass().getSimpleName()); }
  @EventListener void denied(AuthorizationDeniedEvent<?> e) {
    log.warn("authz_fail user={}", e.getAuthentication().get().getName()); } }
```
(With a text layout, add `%replace(%msg){'[\r\n]','_'}` to the Logback pattern.)

### Best-practice checklist
- [ ] A log inventory documents what is logged at each layer, the format, where it is stored, who can access it, and retention (ASVS 16.1.1).
- [ ] Every entry has when/where/who/what metadata. Timestamps are UTC or carry an explicit offset. Clocks are synced (16.2.1, 16.2.2).
- [ ] Logs go only to documented sinks, in a common machine-parseable format (JSON/ECS) (16.2.3, 16.2.4).
- [ ] Sensitive data is logged by protection level. No passwords, tokens, session IDs, keys, connection strings or PAN (16.2.5, 14.2.4). No secrets in URLs (14.2.1).
- [ ] All authentication operations, successes and failures, are logged with the auth type or factor (16.3.1).
- [ ] Failed authorization attempts are logged (L3: all authz decisions and sensitive-data access) (16.3.2).
- [ ] Documented security events and attempts to bypass controls are logged: validation, business logic, anti-automation (16.3.3).
- [ ] Unexpected errors and security-control failures (e.g. backend TLS failures) are logged (16.3.4).
- [ ] All logging components encode data against log injection (16.4.1).
- [ ] Logs are protected from unauthorized access and modification. Append-only or WORM. Access to logs is audited (16.4.2).
- [ ] Logs are shipped securely to a logically separate system for analysis, alerting and escalation (16.4.3).
- [ ] A correlation or trace ID is on every line and propagated across services.
- [ ] Alert rules exist in code, with owners, thresholds, a heartbeat and playbooks. Users are notified of suspicious auth attempts (6.3.5, L3).
- [ ] Logging-failure behaviour has been tested (disk full, collector down). Logging cannot be used to DoS the app.
- [ ] Honeytokens (fake admin account or API key) are deployed with high-fidelity alerts.

### Severity guidance
- **Critical**: credentials, session tokens, API keys, private keys or full card data written to logs that are broadly readable or shipped to a third-party SaaS. Also any log processing that turns input into execution (e.g. Log4j message lookups; usually co-filed under A05:2025 Injection or A03:2025 Supply Chain).
- **High**: no logging of authN or authZ failures on an internet-facing app that handles sensitive data. No alerting at all on brute force or credential stuffing. Logs only on the app host and deletable by the app user. PII or health data logged in bulk.
- **Medium**: CRLF log forging in text logs. Security events missing user, IP or request-ID context. Admin actions not audited. Inconsistent or non-UTC timestamps. Request/response bodies logged on non-auth routes with moderate PII.
- **Low**: unstructured but complete logs. No documented log inventory. Debug-level noise in production with no sensitive data. Missing heartbeat alert when other alerting exists.
- Report items that cannot be verified from code (SOC playbooks, retention, alert routing) as "Needs confirmation", not as findings.

### Sources
- https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/ (redirect target of owasp.org/Top10/2025/A09_…)
- https://top10.owasp.org/2025/0x00_2025-Introduction/
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Logging_Vocabulary_Cheat_Sheet.html
- https://github.com/OWASP/ASVS/blob/master/5.0/en/0x25-V16-Security-Logging-and-Error-Handling.md (plus V6, V14 chapters)
- https://cwe.mitre.org/data/definitions/117.html
- https://github.com/semgrep/semgrep-rules (rule files cited above)
- https://codeql.github.com/codeql-query-help/javascript-cwe/ , …/python-cwe/ , …/java-cwe/ , …/go-cwe/ , …/csharp-cwe/
- https://find-sec-bugs.github.io/bugs.htm
- https://bandit.readthedocs.io/en/latest/plugins/index.html
- https://docs.spring.io/spring-security/reference/servlet/authentication/events.html
- https://docs.spring.io/spring-security/reference/servlet/authorization/events.html
- https://docs.spring.io/spring-boot/reference/features/logging.html
- https://github.com/spring-projects/spring-boot (SecurityAutoConfiguration: DefaultAuthenticationEventPublisher)
- https://github.com/pinojs/pino-std-serializers/blob/master/lib/req.js
- https://pkg.go.dev/log/slog and https://github.com/golang/go/blob/master/src/log/slog/text_handler.go
- https://learn.microsoft.com/en-us/aspnet/core/fundamentals/error-handling (.NET 10 diagnostics suppression)
- https://docs.djangoproject.com/en/stable/howto/error-reporting/
- https://laravel.com/docs/12.x/errors
- https://logging.apache.org/log4j/2.x/manual/layouts.html
- https://www.nist.gov/news-events/news/2025/04/nist-revises-sp-800-61-incident-response-recommendations-and-considerations
- https://explore.kirkpatrickprice.com/videos/pci-v4-0-10-5-1-retain-audit-log-history-for-at-least-12-months
- https://www.zaproxy.org/docs/alerts/
