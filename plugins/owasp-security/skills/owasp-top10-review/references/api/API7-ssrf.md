## API7:2023 – Server Side Request Forgery
**Edition notes:** New to the API list in 2023, with no 2019 equivalent. On the web list it was A10:2021 SSRF; the 2025 introduction says SSRF "has been rolled into" A01.
**Maps to Top 10:2025: A01** (Broken Access Control, where CWE-918 is mapped).

### What it is (issue)
The API fetches a remote resource using a URL, or a host, port or path fragment, that the client supplied, without validating where the request actually goes. The server can then be made to call internal services, localhost admin ports, cloud metadata (`169.254.169.254`) or arbitrary third parties, bypassing firewalls and VPNs. In basic SSRF the response comes back to the attacker; in blind SSRF only timing or side effects leak. Official ratings: Exploitability Easy, Prevalence Common, Detectability Easy, Technical impact Moderate.

### Root causes
- Some features fetch user URLs by design: webhooks (especially "send test request"), URL import, link preview or unfurl, avatar-from-URL, HTML-to-PDF rendering, custom SSO or OIDC discovery with a user-given issuer, and "test connection" buttons.
- Code validates the string, not the destination. Prefix, substring or unanchored-regex checks, and denylists of `localhost`/`127.0.0.1` that never resolve DNS, fall to alternate IP encodings, IPv6 and IPv4-mapped addresses.
- Time-of-check versus time-of-use. The code resolves and checks once, then the HTTP client resolves again (DNS rebinding) or follows a redirect after validation.
- The validator and the HTTP client parse URLs differently (Snyk's "URL confusion" research).
- Flat networks. IMDSv1 is allowed, egress is unfiltered, and the K8s API, Docker API and admin consoles are all reachable over HTTP.
- The raw upstream response is returned to the caller.

### Key CWEs
- ★ CWE-918 Server-Side Request Forgery (SSRF), the official mapping (A01:2025)
- ★ CWE-601 URL Redirection to Untrusted Site. An open redirect on an allowlisted host becomes an SSRF pivot (A01:2025).
- ★ CWE-611 Improper Restriction of XML External Entity Reference. XXE is an SSRF vector (A02:2025).
- ★ CWE-441 Unintended Proxy or Intermediary ('Confused Deputy'), the parent of CWE-918
- ★ CWE-367 Time-of-check Time-of-use Race Condition, which covers DNS rebinding
- CWE-20 Improper Input Validation

### How to detect — code review
- **Stack-agnostic:** list every outbound HTTP sink and trace its URL back to request data, including stored values such as webhook URLs saved earlier. Include indirect sinks: headless browsers (`page.goto`), wkhtmltopdf and WeasyPrint, ImageMagick or ffmpeg given URLs, XML parsers with DTDs enabled, `git clone <url>`, and S3 "custom endpoint" settings. For each sink, check for a scheme allowlist (http/https only), a host allowlist, an IP check after DNS resolution with the connection pinned to that IP, disabled redirects, timeouts and size caps, and no echoing of the raw body.
- **Node:** `(axios(\.\w+)?|got|fetch|needle|superagent|undici\.request|https?\.get)\(\s*[^)]*(req\.(body|query|params)|url)`, and `page\.goto\(`. Next.js: `images.remotePatterns` with `hostname: '\*\*'`, `NextResponse\.rewrite\(new URL\(` built from user input, `NextResponse\.next\(\{\s*headers` (CVE-2025-57822, fixed in 14.2.32 and 15.4.7), and Next < 14.1.1 (CVE-2024-34351, Server Actions SSRF via Host header).
- **Python:** `requests\.(get|post|head|request)\(|httpx\.|urlopen\(|aiohttp` fed by `request\.(args|form|json|GET|POST|data)`. Pydantic `HttpUrl`/`AnyUrl` fields only validate format, not destination. `requests` follows redirects by default.
- **Java:** `new URL\(.*\)\.(openConnection|openStream)|RestTemplate|WebClient|HttpClient\.newHttpClient` with `@RequestParam String url`. `HttpURLConnection` follows redirects by default.
- **Go:** `http\.(Get|Post|Head)\(|http\.NewRequest(WithContext)?\(|\.Do\(req\)` with `r\.URL\.Query\(\)\.Get|r\.FormValue`. `http.DefaultClient` follows up to 10 redirects.
- **PHP/Laravel:** `file_get_contents\(\$|fopen\(\$|curl_setopt\(.*CURLOPT_URL|Http::(get|post)\(\$request`. Also `CURLOPT_FOLLOWLOCATION,\s*true`, and a missing `CURLOPT_PROTOCOLS` restriction, which leaves `file://` and `gopher://` open.
- **.NET:** `(GetAsync|GetStringAsync|SendAsync|DownloadString)\(` or `WebRequest\.Create\(` with a URL from `[FromQuery]`/`[FromBody]`. `HttpClientHandler.AllowAutoRedirect` defaults to true.
- **Validation smells:** `startsWith("https://trusted` (defeated by `trusted.evil.tld` or `user@host`), `.includes(`, regexes without anchors, hostname-string denylists, validating one string and then fetching a re-built one, and allowlisting after following redirects.
- **GraphQL:** mutations that create webhooks or notification channels with a URL argument (the official scenario #2).
- **False positives:** the URL comes only from server config or env; a fixed host where only a path segment varies (check path encoding; this is partial SSRF and lower risk); outbound traffic forced through an egress proxy that enforces an allowlist (confirm this in deployment config).

### How to detect — runtime (safe, own app only)
Start a canary listener: `python3 -m http.server 9999 --bind 127.0.0.1`. Submit each URL below to the URL-taking feature. Expect a 4xx validation error and **no hit** in the listener log.
- `http://127.0.0.1:9999/canary`, `http://localhost:9999/`, `http://[::1]:9999/`, `http://127.1:9999/`, `http://2130706433:9999/` (decimal IP), `http://[::ffff:127.0.0.1]:9999/`
- `http://127.0.0.1.nip.io:9999/`. Public DNS resolves this to 127.0.0.1, which tests whether the app checks the resolved IP.
- `file:///etc/hostname` and `gopher://127.0.0.1:9999/`, to test the scheme allowlist.
- `http://169.254.169.254/`. It should be rejected before any request goes out; confirm in the egress logs.
- **Redirects:** point at an allowed test host that returns `302 Location: http://127.0.0.1:9999/`. The redirect must not be followed.
- **Oracle:** error messages and timings should not distinguish open from closed internal ports.
- **IMDSv2 (on the host):** `curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/` should return `401` when tokens are required.

### Tools
- Semgrep rule files: `python/flask/security/injection/ssrf-requests.yaml`, `python/django/security/injection/ssrf/ssrf-injection-requests.yaml`, `python/{flask,django}/security/injection/tainted-url-host.yaml`, `javascript/express/security/audit/express-ssrf.yaml`, `java/spring/security/injection/tainted-url-host.yaml`, `go/lang/security/injection/tainted-url-host.yaml`, `php/lang/security/injection/tainted-url-host.yaml`, `csharp/lang/security/ssrf/{http-client,web-client,web-request,rest-client}.yaml`.
- CodeQL: `js/request-forgery`, `py/full-ssrf` (plus `py/partial-ssrf`), `java/ssrf`, `go/request-forgery`, and `cs/request-forgery` (experimental). gosec: `G107` (URL provided to HTTP request as taint input).
- Spectral OWASP: `owasp:api7:2023-concerning-url-parameter` flags URL-like parameters in the spec.
- IaC: Checkov `CKV_AWS_79` (IMDSv1 must not be enabled) and Trivy `AVD-AWS-0028` (IMDS should require tokens). Live instances: `aws ec2 describe-instances --query "Reservations[].Instances[].MetadataOptions"`.
- Defensive libraries: Node `request-filtering-agent` (use ≥ 2.0.0; CVE-2025-57814 was an HTTPS-to-127.0.0.1 bypass), Go `github.com/doyensec/safeurl`, Python stdlib `ipaddress`, Java Apache Commons Validator `InetAddressValidator`/`DomainValidator`. Egress proxy: Stripe Smokescreen.

### Fix / remediation
Best: don't accept full URLs at all. Take an ID or pick from a host allowlist and build the URL server-side. If arbitrary external URLs are a business need (webhooks), do all of the following:
1. Allow only `https` (and `http` if you must) and ports 443/80.
2. Resolve **every** A and AAAA record and reject any non-public IP. That covers 127/8, 0/8, 10/8, 172.16/12, 192.168/16, 169.254/16 (IMDS at .169.254, ECS task metadata at 169.254.170.2), 100.64/10, `::1`, `fc00::/7` (includes AWS IPv6 IMDS `fd00:ec2::254`), `fe80::/10`, IPv4-mapped `::ffff:0:0/96` and multicast.
3. **Pin** the connection to the IP you checked.
4. Disable redirects.
5. Set timeouts and size and content-type caps.
6. Never return the raw response.
7. Enforce an egress allowlist at the network layer.
8. Require IMDSv2: `aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled`.
```python
# BAD
requests.get(request.json["url"])                        # any scheme/host, follows redirects, no timeout
# GOOD (allowlist + resolved-IP check; add an egress proxy for rebinding-proof pinning)
u = urlsplit(url)
if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS or u.port not in (None, 443): abort(400)
for *_, sa in socket.getaddrinfo(u.hostname, 443):
    ip = ipaddress.ip_address(sa[0]); ip = getattr(ip, "ipv4_mapped", None) or ip
    if not ip.is_global: abort(400)
r = requests.get(url, timeout=(3, 10), allow_redirects=False, stream=True)
```
```go
// Go: check the *actual* dialed IP (defeats DNS rebinding), no redirects, no env proxy, timeouts
// var _, cgnat, _ = net.ParseCIDR("100.64.0.0/10")
d := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, addr string, _ syscall.RawConn) error {
    host, _, _ := net.SplitHostPort(addr); ip := net.ParseIP(host)
    if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() ||
        ip.IsMulticast() || cgnat.Contains(ip) { return errors.New("blocked destination") }
    return nil }}
client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: d.DialContext, Proxy: nil},
    CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
```
```js
// Node (axios/node-fetch/got accept an agent; native fetch needs an undici dispatcher instead)
import { useAgent } from "request-filtering-agent";          // >= 2.0.0
const u = new URL(input); if (u.protocol !== "https:" || !ALLOWED.has(u.hostname)) throw new Error("blocked");
await axios.get(u.href, { httpsAgent: useAgent(u.href), maxRedirects: 0, timeout: 5000, maxContentLength: 5_000_000 });
```

### Best-practice checklist
- [ ] Outbound calls built from untrusted data are validated against an allowlist of protocols, domains, paths and ports (ASVS 1.3.6)
- [ ] One consistent URL parser is used for both validation and fetching (ASVS 1.5.3)
- [ ] An allowlist of external systems exists at the app and/or network layer (ASVS 13.2.4, 13.2.5), and user-supplied destinations are documented (ASVS 13.1.1)
- [ ] Redirects are not followed unless intended (ASVS 15.3.2)
- [ ] All resolved IPs are checked, the connection is pinned, and private, link-local and metadata ranges are blocked, IPv6 and mapped forms included
- [ ] Timeouts, response size caps and a content-type allowlist are set; raw responses are never echoed
- [ ] IMDSv2 is required (hop limit set deliberately); GCP and Azure metadata need headers (`Metadata-Flavor: Google`, `Metadata: true`) but still get blocked by IP
- [ ] Fetchers run in an isolated network segment or behind an egress proxy
- [ ] XML parsers have external entities disabled (ASVS 1.5.1)

### Severity guidance
- **Critical:** full-read SSRF that reaches cloud credentials (IMDSv1, ECS 169.254.170.2) or unauthenticated internal admin APIs (K8s, Docker, actuator), or SSRF that any anonymous user can trigger.
- **High:** full-read SSRF into the internal network by a low-privilege user; blind SSRF where state-changing internal GET endpoints or IMDSv1 are reachable.
- **Medium:** blind SSRF limited to port scanning or timing; an allowlist that can be bypassed only via an open redirect on an allowed host; no IP pinning while other controls hold.
- **Low:** fetching restricted to external hosts (open-proxy or IP-masking abuse) with timeouts and size caps; a URL that only an admin can configure.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/ (and raw .md on GitHub)
- https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/ and 2025 Introduction (github.com/OWASP/Top10/tree/master/2025/docs/en)
- https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/918.html ; https://snyk.io/blog/url-confusion-vulnerabilities/
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-existing-instances.html
- https://github.com/advisories/GHSA-pw25-c82r-75mm (CVE-2025-57814) ; https://github.com/azu/request-filtering-agent ; https://github.com/doyensec/safeurl
- https://vercel.com/changelog/cve-2025-57822 ; https://github.com/vercel/next.js/security/advisories/GHSA-fr5h-rqp8-mj6g (CVE-2024-34351)
- https://docs.bridgecrew.io/docs/bc_aws_general_31 ; https://avd.aquasec.com/misconfig/aws/ec2/avd-aws-0028/
- https://github.com/github/codeql (query IDs checked) ; https://github.com/semgrep/semgrep-rules (paths checked)

---
