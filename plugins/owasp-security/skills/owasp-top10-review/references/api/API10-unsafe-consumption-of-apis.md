## API10:2023 – Unsafe Consumption of APIs
**Edition notes:** New in 2023. It targets attackers who compromise *integrated* services rather than the target API directly. It partly takes over from API8:2019 Injection (its scenarios are injection through third-party data). Official CWEs: CWE-20, CWE-200, CWE-319.
**Maps to Top 10:2025: A08** (Software or Data Integrity Failures: CWE-345, CWE-829) and **A05** (Injection, CWE-20). Also A04 (CWE-319 cleartext), A07 (CWE-295 certificate validation is mapped there) and A10 (missing timeouts and limits, failing open).

### What it is (issue)
The API trusts the data and behavior of upstream APIs (payment, address enrichment, OAuth or identity providers, SaaS, partner APIs, webhooks, LLMs) more than it trusts user input. Typical gaps: no TLS or certificate validation; no schema validation or sanitization before the data reaches a DB, HTML or shell; redirects followed blindly (re-sending sensitive bodies to attacker hosts, official scenario #2); and no timeouts or size limits. A compromised or malicious upstream then turns into injection, data exfiltration or DoS. Official ratings: Exploitability Easy, Prevalence Common, Detectability Average, Technical impact Severe.

### Root causes
- Trust bias toward "well-known providers". Upstream data isn't treated as untrusted input, and SAST taint sources usually model only inbound request data.
- Unsafe HTTP client defaults. No timeout: Python `requests`, axios (`timeout: 0`), Go `http.DefaultClient`, Guzzle. Redirects followed automatically: requests, axios, native `fetch`, .NET `HttpClient` and Guzzle.
- TLS verification disabled "temporarily" for a staging certificate, which then ships to prod.
- Deserialization into dynamic or polymorphic types, and upstream JSON spread straight into ORM models (mass assignment from a third party).
- Webhooks accepted without signature, timestamp or replay checks. No circuit breaker, so the service fails open or cascades.
- LLM output treated as trusted and passed to SQL, a shell or HTML (compare OWASP LLM05:2025 Improper Output Handling).

### Key CWEs
- ★ CWE-20 Improper Input Validation, official (A05:2025)
- ★ CWE-319 Cleartext Transmission of Sensitive Information, official (A04:2025)
- ★ CWE-295 Improper Certificate Validation (A07:2025)
- ★ CWE-345 Insufficient Verification of Data Authenticity, which covers unsigned webhooks (A08:2025)
- ★ CWE-89 / CWE-79 SQL injection and XSS through third-party data (A05:2025)
- ★ CWE-770 Allocation of Resources Without Limits or Throttling (no timeouts or size caps)
- CWE-200 Exposure of Sensitive Information to an Unauthorized Actor, official; CWE-502 Deserialization of Untrusted Data; CWE-636 Not Failing Securely (A10:2025)

### How to detect — code review
- **Stack-agnostic:** list every integration (SDK clients plus raw HTTP; check client factories and DI config). For each, answer these questions. Is TLS on and verified? Are connect and read timeouts and an overall deadline set? Are redirects off or allowlisted? Is the response size capped? Is the response schema validated (types, lengths, enums) before use? Is data parameterized or encoded when stored or rendered? Are retries bounded, with backoff and a circuit breaker? Does it fail closed? Are credentials kept from being forwarded on redirect? Are webhooks signed and timestamped?
- **Node:** `rejectUnauthorized:\s*false`, `NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0`; `axios(\.create)?\(` with no `timeout`; `fetch\(` with no `signal` (use `AbortSignal.timeout`) and the default `redirect: "follow"`; `\.\.\.(data|body|resp)` spread into `create(`/`update(`; unbounded `res.text()` or `res.json()`.
- **Python:** `requests\.\w+\((?![^)]*timeout)`, `verify\s*=\s*False`, `ssl\._create_unverified_context`, f-string or `%` SQL built from `resp.json()`. `httpx` defaults are safer (5 s timeout, no redirects), so flag `follow_redirects=True` or `verify=False`.
- **Java:** `new RestTemplate\(\)` with no timeouts; `X509TrustManager` whose `checkServerTrusted` has an empty body; `NoopHostnameVerifier`; `activateDefaultTyping|enableDefaultTyping` on upstream JSON. `HttpURLConnection` follows redirects by default; `java.net.http.HttpClient` defaults to `Redirect.NEVER`.
- **Go:** `http\.(Get|Post)\(|http\.DefaultClient` (no timeout, up to 10 redirects); `io\.ReadAll\(resp\.Body\)` without `io.LimitReader`; `InsecureSkipVerify:\s*true`.
- **PHP/Laravel:** Guzzle `'verify'\s*=>\s*false` (its defaults are no timeout and redirects on); `CURLOPT_SSL_VERIFYPEER,\s*(false|0)`, `CURLOPT_SSL_VERIFYHOST,\s*0`; `Http::withoutVerifying\(\)`; `unserialize\(` on upstream data. The Laravel `Http` client defaults to a 30 s timeout.
- **.NET:** `ServerCertificateCustomValidationCallback\s*=.*=>\s*true`, `DangerousAcceptAnyServerCertificateValidator`, `TypeNameHandling\.(All|Auto|Objects)` (Newtonsoft). `HttpClient` defaults to a 100 s timeout and `AllowAutoRedirect=true`.
- **Webhooks and GraphQL:** a handler that parses the body before verifying the HMAC or signature (e.g. Stripe `constructEvent`, `timingSafeEqual`/`hmac.compare_digest`) or skips the timestamp tolerance check. A federation gateway or stitched remote schema that trusts subgraph data.
- **False positives:** `verify=False` or `InsecureSkipVerify` only in tests or local tooling; timeouts set centrally (`AddHttpClient`, `axios.create`, a `requests.Session` adapter); TLS handled by a mesh sidecar with mTLS.

### How to detect — runtime (safe, own app only)
Point the integration's base URL at a local mock (WireMock, mockttp or Toxiproxy) through staging config, then check each case:
- **Redirect:** the mock returns `308 Location: http://127.0.0.1:9999/`. A canary listener on 9999 must receive nothing.
- **Latency:** the mock waits 60 s (WireMock `fixedDelayMilliseconds`, or a Toxiproxy `latency` toxic). The app must time out within budget and return a graceful error without exhausting its worker pool.
- **Oversized body:** the mock returns 100 MB or streams forever. The app must abort at its size cap.
- **Schema abuse:** wrong types, extra fields (`"role":"admin"`), overlong strings, and strings containing quotes or `<b>` markers. The app must reject or encode; no DB error, no unencoded reflection, no privilege field applied.
- **TLS:** serve the mock over a self-signed or expired certificate. The connection must fail.
- **Webhooks:** send one unsigned, one bad-signature and one replayed (old timestamp) webhook to your endpoint. Expect 400 or 401 and no state change.

### Tools
- Semgrep: `python/requests/security/disabled-cert-validation.yaml`, `python/lang/security/audit/insecure-transport/requests/request-with-http.yaml`, `python/requests/security/no-auth-over-http.yaml`, `problem-based-packs/insecure-transport/js-node/bypass-tls-verification.yaml`, `problem-based-packs/insecure-transport/js-node/disallow-old-tls-versions1.yaml`, `go/lang/security/audit/crypto/missing-ssl-minversion.yaml`. For the injection path, write a custom taint rule whose *source* is the HTTP-client response.
- CodeQL: `js/disabling-certificate-validation`, `py/request-without-cert-validation`, `go/disabled-certificate-check`, `java/insecure-trustmanager`.
- Bandit `B113` (request without timeout) and `B501` (no cert validation); gosec `G402` (TLS InsecureSkipVerify).
- Test doubles: WireMock, Toxiproxy, mockttp. SCA on SDKs: `osv-scanner`.

### Fix / remediation
```python
# BAD
data = requests.get(PARTNER_URL + q, verify=False).json(); db.execute(f"INSERT ... '{data['name']}'")
# GOOD: TLS verified, timeouts, no redirects, size cap, schema validation, parameterized SQL
class Biz(BaseModel): name: constr(max_length=200); zip: constr(pattern=r"^\d{5}$")
with httpx.Client(timeout=httpx.Timeout(5.0, connect=2.0), follow_redirects=False) as c:
    r = c.get(PARTNER_URL, params={"q": q}); r.raise_for_status()
    if int(r.headers.get("content-length", 0)) > 1_000_000: raise ValueError("too large")
    biz = Biz.model_validate_json(r.content)
db.execute("INSERT INTO biz(name, zip) VALUES (%s, %s)", (biz.name, biz.zip))
```
```js
// Node (native fetch + zod)
const Biz = z.object({ name: z.string().max(200), zip: z.string().regex(/^\d{5}$/) }).strict();
const r = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5000) });   // 3xx -> treat as error
if (r.status !== 200 || Number(r.headers.get("content-length") ?? 0) > 1e6) throw new Error("bad upstream");
const biz = Biz.parse(await r.json());      // never spread raw upstream JSON into models or SQL
```
```go
client := &http.Client{Timeout: 5 * time.Second,
    CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
resp, err := client.Do(req); if err != nil { return err }; defer resp.Body.Close()
body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)); // then json.Unmarshal into a typed struct + validate
```
Also: vet each provider's security posture. Pin certificates or trust anchors only for internal mTLS. Use an allowlist for redirect targets. Wrap calls in a circuit breaker (resilience4j, Polly/`AddStandardResilienceHandler`, opossum, sony/gobreaker). Verify webhook signatures over the raw body with timestamp tolerance. Treat LLM output as untrusted input.

### Best-practice checklist
- [ ] Every inbound and outbound connection uses TLS (ASVS 12.3.1), and TLS clients validate certificates (ASVS 12.3.2)
- [ ] Integrations are documented with their resource strategy: timeouts, retry limits, backoff (ASVS 13.1.1, 13.1.3), and connections follow that documented config (ASVS 13.2.6)
- [ ] An allowlist defines which external systems the app may call (ASVS 13.2.4)
- [ ] Redirects are not followed unless intended (ASVS 15.3.2)
- [ ] Upstream data is validated against a positive schema (ASVS 2.2.1), with parameterized queries and contextual encoding (ASVS 1.2.4, 1.2.1)
- [ ] No unsafe deserialization of upstream data (ASVS 1.5.2)
- [ ] The app stays secure when upstreams fail, via circuit breakers or degradation (ASVS 16.5.2), and fails closed (ASVS 16.5.3)
- [ ] Response size and concurrency limits exist per integration
- [ ] Webhooks are signed and timestamped with replay protection; highly sensitive messages are signed (ASVS 4.1.5, L3)

### Severity guidance
- **Critical:** upstream data reaching SQL, command or deserialization sinks without validation; TLS verification disabled in prod on a channel carrying credentials, tokens or PHI; automatic redirects that re-send sensitive payloads or auth headers.
- **High:** unsigned webhooks that change state (marking an order paid); upstream data rendered as HTML without encoding (stored XSS); plaintext HTTP to a third party carrying PII.
- **Medium:** no timeouts or size limits (thread or memory exhaustion); failing open on upstream errors; no schema validation where the data only reaches safe sinks.
- **Low:** no documented provider assessment or integration inventory; retries without backoff.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/ (and raw .md)
- https://owasp.org/API-Security/editions/2023/en/0x04-release-notes/
- https://top10.owasp.org/2025/ (A04, A05, A07, A08, A10 pages via github.com/OWASP/Top10 2025/docs/en)
- https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (V1, V2, V4, V12, V13, V15, V16)
- https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html ; https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html ; https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
- https://github.com/github/codeql (query IDs checked) ; https://github.com/semgrep/semgrep-rules (paths checked)
