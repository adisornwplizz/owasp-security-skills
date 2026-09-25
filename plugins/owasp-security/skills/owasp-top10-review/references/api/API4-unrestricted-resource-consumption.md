## API4:2023 – Unrestricted Resource Consumption
**Edition notes:** Replaces API4:2019 "Lack of Resources & Rate Limiting". The focus moved from request rate to the resources consumed (CPU, memory, storage, bandwidth) and to **paid** third-party resources (SMS, email, biometrics, cloud egress). Business-flow abuse that rate limiting mainly mitigates moved to the new API6:2023. Official rating: exploitability Average, prevalence Widespread, detectability Easy, impact Severe.
**Maps to Top 10:2025: A06 / A10 (partial).** There is no direct 2025 category, and CWE-770/CWE-400 appear in no 2025 mapping list. The closest matches:
- **A06** (Insecure Design), which includes CWE-799 (Improper Control of Interaction Frequency).
- **A10** (Mishandling of Exceptional Conditions), whose text says to add "rate limiting, resource quotas, throttling… Nothing in information technology should be limitless".
- **A02** (Security Misconfiguration) for server and proxy limits.

For LLM features, also see OWASP **LLM10:2025 Unbounded Consumption**.

### What it is (issue)
Any request that can consume server or paid resources without bound. Examples:
- Unlimited page sizes, request bodies, array lengths or string lengths.
- File uploads with no limit on size, unpacked size, file count or image pixels.
- GraphQL queries with no limit on depth, aliases or batching.
- Long operations with no timeout, and unbounded concurrency or streams.
- Per-request calls to paid providers (SMS/OTP, email, LLM tokens, maps, KYC) with no quota or spending cap.

The outcome is denial of service, degraded service, or runaway bills ("denial of wallet").

### Root causes
- Framework defaults are unbounded or generous. Verified examples:
  - Flask `MAX_CONTENT_LENGTH=None`.
  - DRF `PAGE_SIZE=None`, with `max_page_size` and `max_limit` also `None`.
  - grpc-go `MaxConcurrentStreams` = MaxUint32 and a 4 MiB receive limit.
  - Kestrel's maximum body is 30,000,000 bytes.
  - Go `http.Server` timeouts default to 0, which means none.
  - .NET `HttpClient` times out only after 100 s.
- Client-controlled `limit`/`size`/`per_page`/`first` values go straight into queries.
- Limits are applied per HTTP request, but one request can carry many operations (GraphQL batches or aliases, bulk endpoints, ID arrays).
- Rate limiting is missing, keyed only by IP (bypassed through spoofed `X-Forwarded-For` when proxy trust is misconfigured), or held in per-instance memory.
- Unauthenticated endpoints trigger paid third-party calls, and there are no provider-side spend caps or alerts.
- Outbound HTTP and DB queries have no timeouts, regexes are ReDoS-prone, and heavy work (images, PDFs, LLM calls) runs synchronously in the request path.

### Key CWEs
- ★ **CWE-770** Allocation of Resources Without Limits or Throttling (official) · ★ **CWE-400** Uncontrolled Resource Consumption (official)
- ★ **CWE-799** Improper Control of Interaction Frequency (official)
- ★ **CWE-1333** Inefficient Regular Expression Complexity · ★ **CWE-409** Improper Handling of Highly Compressed Data
- CWE-674 Uncontrolled Recursion (deep GraphQL/JSON) · CWE-834 Excessive Iteration

### How to detect — code review
**Stack-agnostic:** Draw up the limit inventory and find where each limit is enforced (app, gateway, nginx `client_max_body_size`/`limit_req`, IaC):
- Body size and per-field string length.
- Array size and page size.
- Upload size, unpacked size and file count.
- GraphQL depth, cost, aliases and batch size.
- Execution, DB-statement and outbound-HTTP timeouts.
- Concurrency and streams.
- Per-user and per-operation quotas.
- Third-party spend caps.

Then check the runtime ceilings: compose `deploy.resources.limits`, k8s `resources.limits`, Lambda timeout and memory. Finally, grep for paid-provider calls (`twilio|messages\.create|sendgrid|ses\.send|openai|anthropic|chat\.completions`) and check each one for auth, a per-user quota, a provider cap and `max_tokens`.
- **Node:** `express\.json\(\s*\{[^}]*limit:\s*['"]\d{2,}mb` (the body-parser default is `100kb`) · `multer\(\{` without `limits` · `req\.query\.(limit|take|pageSize|per_page|first)` flowing into `.limit(`/`take:` without clamping · no `express-rate-limit|@nestjs/throttler|rate-limiter-flexible` · `new ApolloServer\(` without depth/cost rules · `allowBatchedHttpRequests:\s*true` (the Apollo default is false) · `new RegExp\(req\.`.
- **Python:** DRF `page_size_query_param` without `max_page_size`, or `LimitOffsetPagination` without `max_limit` · `DATA_UPLOAD_MAX_MEMORY_SIZE\s*=\s*None` (the default is 2.5 MB) · a Flask app with no `MAX_CONTENT_LENGTH` · FastAPI with no body cap (Starlette ≥ 1.6 has `RequestBodyLimitMiddleware(max_body_size=...)`; otherwise cap at the proxy) · `requests\.(get|post|put|delete)\(` without `timeout=` (Bandit B113) · Graphene/Strawberry without `depth_limit_validator`/`QueryDepthLimiter`.
- **Java:** `spring\.servlet\.multipart\.max-(file|request)-size\s*=\s*-1` · `spring\.data\.web\.pageable\.max-page-size` raised (default 2000) · `PageRequest\.of\(\s*\w+\s*,\s*\w+\s*\)` with a request-derived size · RestTemplate/WebClient without timeouts · graphql-java without `MaxQueryDepthInstrumentation`/`MaxQueryComplexityInstrumentation`.
- **Go:** `http\.ListenAndServe\(` (gosec G114) · `http\.Server\{` without `ReadHeaderTimeout` (G112) · `io\.ReadAll\(r\.Body\)` without `http\.MaxBytesReader` · `http\.Get\(|&http\.Client\{\}` (no Timeout) · `grpc\.NewServer\(` without `MaxConcurrentStreams|KeepaliveEnforcementPolicy` or with a huge `MaxRecvMsgSize` · gqlgen without `extension\.FixedComplexityLimit`.
- **PHP/Laravel:** API routes without `throttle:` · `->paginate\(\s*\$request->(input|get|query)\(` without `min()` · php.ini `memory_limit\s*=\s*-1|max_execution_time\s*=\s*0`.
- **.NET:** `MaxRequestBodySize\s*=\s*null` · `\[DisableRequestSizeLimit\]` · no `AddRateLimiter`/`UseRateLimiter` · `\.Take\(\s*(pageSize|limit|take)\s*\)` without clamping · Hot Chocolate `EnforceCostLimits\s*=\s*false` (on by default).
- **gRPC:** handlers that ignore `ctx` deadlines/cancellation, and server-streaming loops with no bound.
- **False positives:** limits enforced by a gateway, CDN, WAF or API-gateway usage plan (verify in repo or IaC); internal admin-only batch endpoints.

### How to detect — runtime (safe, own app only; small volumes)
- **Pagination:** `curl -s -H "Authorization: Bearer $TA" 'localhost:8080/api/items?limit=100000' | jq length`. Expect results clamped to the documented maximum, or a 400.
- **Body size:** `python3 -c 'print("{\"a\":\""+"x"*20_000_000+"\"}")' | curl -s -o /dev/null -w '%{http_code}\n' -H 'Content-Type: application/json' --data-binary @- localhost:8080/api/items`. Expect a fast 413, not a 500 or a hang. For bulk endpoints, send 10,000 array items and expect 400.
- **Rate limit:** `for i in $(seq 30); do curl -s -o /dev/null -w '%{http_code} ' -H "Authorization: Bearer $TA" localhost:8080/api/search?q=a; done`. Expect 429 with `Retry-After` or `RateLimit` headers after the documented threshold. Adding `X-Forwarded-For: 10.0.0.$i` must not reset the counter.
- **GraphQL:** a depth-15 nested query, 100 aliases and a batch of 50 operations should each be rejected at validation time, not executed.
- **Paid providers:** in staging with sandbox credentials, request an OTP five times for the same number and expect throttling. Confirm provider spend caps and alerts exist; those live in the provider console, not in code.
- **Timeouts:** point one dependency at a slow stub and confirm the request fails fast and frees its resources.

### Tools
- **Linters/SAST:** gosec G112/G114/G110 (decompression bomb) and Bandit B113. CodeQL: `js/missing-rate-limiting`, `js/resource-exhaustion`, `js/resource-exhaustion-from-deep-object-traversal`, `go/uncontrolled-allocation-size`, `js/redos`, `js/polynomial-redos`, `py/redos`, `py/polynomial-redos`, `java/redos`, `java/polynomial-redos`.
- **Spectral OWASP:** `owasp:api4:2023-rate-limit`, `-rate-limit-retry-after`, `-rate-limit-responses-429`, `-array-limit`, `-string-limit`, `-string-restricted`, `-integer-limit`, `-integer-format`.
- **GraphQL:** `python3 graphql-cop.py -t http://localhost:4000/graphql -H '{"Authorization":"Bearer ..."}'`, which tests alias, batch, directive and field-duplication DoS, introspection and suggestions. Its DoS probes are heavy, so run them on local builds only. GraphQL Armor (`ApolloArmor`/`EnvelopArmor`: maxDepth, maxAliases, maxDirectives, maxTokens, costLimit, blockFieldSuggestion) is the fix-side library.
- **Staging-only verification:** k6/vegeta at a low RPS; Schemathesis `--rate-limit 10/s` to stay gentle.

### Fix / remediation
```js
// Express — body cap + global and per-route limits + clamped page size
app.use(express.json({ limit: '100kb' }));
app.use(rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: 'draft-8', legacyHeaders: false }));
const take = Math.min(Number(req.query.limit) || 20, 100);
const server = new ApolloServer({ schema, ...new ApolloArmor({ maxDepth: { n: 8 }, costLimit: { maxCost: 5000 } }).protect() });
```
```go
// Go — timeouts, body cap, gRPC limits
srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
    WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
g := grpc.NewServer(grpc.MaxRecvMsgSize(1<<20), grpc.MaxConcurrentStreams(100))
```
```python
# DRF — bounded pagination + throttles
class Page(PageNumberPagination): page_size = 20; page_size_query_param = "size"; max_page_size = 100
REST_FRAMEWORK = {"DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.UserRateThrottle"],
                  "DEFAULT_THROTTLE_RATES": {"user": "100/min"}}
```
Also:
- Key quotas by user or API key as well as IP, and use a shared store (Redis) across instances.
- Configure proxy trust to exact hops (ASVS 15.3.4).
- Cap per-operation paid calls: one OTP per number per N minutes, LLM `max_tokens` plus a per-user daily token budget.
- Set provider spending limits, or billing alerts where limits are not available.
- Move heavy work to queues.
- Set statement timeouts, container memory/CPU limits and pids limits.

### Best-practice checklist
- [ ] Business limits per user and globally are documented (ASVS 2.1.3) and implemented (2.3.2). Anti-automation protects costly functions (2.4.1).
- [ ] GraphQL uses an allowlist, depth, amount or cost limiting (4.3.1); batching is disabled or counted per operation.
- [ ] Upload size (5.2.1), unpacked size and file count (5.2.3), and per-user quotas (5.2.4, L3) are enforced.
- [ ] Resource-heavy functions are identified and defended (15.1.3, 15.2.2). Connection pools, timeouts and retries are defined for each dependency (13.1.2, 13.1.3, 13.2.6).
- [ ] Page size is clamped server-side; body, string and array limits are in the schema and enforced; responses are 413/429 with `Retry-After`.
- [ ] Rate limiting uses the real client IP from trusted proxy headers only (15.3.4). Third-party spend caps and billing alerts are set.

### Severity guidance
- **Critical:** an unauthenticated request can trigger paid actions without bound (SMS/LLM/KYC) or crash/OOM the service. Example: a single GraphQL query or a small upload (decompression bomb) takes the API down.
- **High:** no rate limiting or quotas on expensive authenticated endpoints; unbounded page size on large tables; no timeouts on outbound calls in the request path.
- **Medium:** limits exist but are far too high, are only per IP or per instance, or miss one dimension (e.g., aliases); missing spend alerts.
- **Low:** missing `Retry-After`/rate-limit headers; limits set slightly above need on low-cost endpoints.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/ · https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://owasp.org/Top10/2025/A06_2025-Insecure_Design/ · https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/ · https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/
- ASVS 5.0 V2/V4/V5/V13/V15 · https://www.apollographql.com/docs/apollo-server/api/apollo-server · https://chillicream.com/docs/hotchocolate/v15/security/cost-analysis
- https://strawberry.rocks/docs/extensions/query-depth-limiter · https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/kestrel/options
- grpc-go `server.go` (default options) · PyPI flask 3.1.3, djangorestframework 3.18.1, django 5.2, starlette 1.7.0 source · npm body-parser, express-rate-limit 8.7, @escape.tech/graphql-armor 3.2 · github.com/dolevf/graphql-cop · github.com/securego/gosec RULES.md

---
