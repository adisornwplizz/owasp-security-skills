## API2:2023 – Broken Authentication
**Edition notes:** Renamed from API2:2019 "Broken User Authentication". The scope now covers all authentication, including microservices reachable without auth and weak or predictable tokens. Official rating: exploitability Easy, prevalence Common, detectability Easy, impact Severe. A Sept 2026 `develop` edit now reads "API keys ... should only be used for API clients **authorization**" (it previously said "authentication").
**Maps to Top 10:2025: A07** (Authentication Failures): CWE-287, 306, 307, 384, 521, 613, 620, 640, 798 and 1390–1393 are A07:2025. JWT signature flaws (CWE-347) and weak password hashing (CWE-916) map to **A04:2025** (Cryptographic Failures). CWE-204 is not mapped in 2025.

### What it is (issue)
The API does a poor job of verifying who is calling. Typical flaws:
- Login, reset and OTP endpoints allow brute force or credential stuffing.
- Tokens are accepted without checking signature, algorithm, expiry, audience or issuer.
- Credentials travel in URLs.
- Password storage is weak.
- Email, password or MFA can be changed without re-authentication.
- Internal services accept unauthenticated calls.

The result is account takeover, and attacker traffic that is indistinguishable from the real user's.

### Root causes
- Home-grown auth and token code. Teams misunderstand the basics: OWASP states "OAuth is not authentication, and neither are API keys".
- Auth endpoints get the same limits as normal endpoints. There are no per-account limits, and forgot-password/OTP flows are not protected the way login is.
- Library defaults are misread: decoding is treated as verifying, algorithm confusion is possible, and `exp`/`aud` checks are skipped.
- Alternate flows (mobile, deep links, legacy `/v1`, GraphQL mutations, gRPC) are not inventoried, and one of them is weaker.
- Trust is implicit inside the network: no mTLS or service tokens, and headers like `X-User-Id` from a gateway are trusted.
- Secrets are hard-coded or too short.

### Key CWEs
- ★ **CWE-307** Improper Restriction of Excessive Authentication Attempts (official) · ★ **CWE-204** Observable Response Discrepancy (official)
- ★ **CWE-287** Improper Authentication · ★ **CWE-347** Improper Verification of Cryptographic Signature (JWT)
- ★ **CWE-306** Missing Authentication for Critical Function (service-to-service)
- ★ **CWE-640** Weak Password Recovery Mechanism · ★ **CWE-620** Unverified Password Change
- CWE-613 Insufficient Session Expiration · CWE-798 Hard-coded Credentials · CWE-916 Weak Password Hash · CWE-521 · CWE-598

### How to detect — code review
**Stack-agnostic:** List every auth flow: login, refresh, logout, register, forgot/reset, MFA/OTP verify, magic links, API keys, OAuth/OIDC callbacks and service tokens. For each flow, check:
- Attempt limits keyed by account *and* client.
- Full token verification: signature, algorithm allowlist, `exp`/`nbf`, `iss`, `aud`, token type.
- Where the secrets come from.
- Password hashing algorithm and parameters.
- Re-authentication before changing email, phone, MFA or password.
- Session/refresh-token revocation on logout and password change.
- No tokens in URLs: `[?&](access_token|token|api_key|apikey|password)=`.
- Gateway and mesh configs that leave internal routes unauthenticated.

Per-stack patterns:
- **Node:** `jwt\.decode\(` used for an auth decision · `algorithms:\s*\[[^\]]*['"]none['"]` · `ignoreExpiration:\s*true` · `jwt\.verify\(` with no `audience`/`issuer` · `secret\w*\s*[:=]\s*['"][^'"]{1,31}['"]` · `bcrypt\.hash(Sync)?\([^,]+,\s*[1-9]\)` (cost < 10) · `createHash\(['"](md5|sha1|sha256)['"]\)` near "password" · login/reset routes without `rateLimit|@Throttle|RateLimiter` · `app\.set\(['"]trust proxy['"],\s*true\)` (clients can spoof their IP and bypass the limiter). Note: jsonwebtoken v9 rejects unsigned tokens unless `"none"` is listed in `algorithms`.
- **Python:** `jwt\.decode\([^)]*verify_signature['"]?\s*:\s*False` · `algorithms=\[[^\]]*['"]none` · `hashlib\.(md5|sha1|sha256)\(` on passwords · Django `PASSWORD_HASHERS` containing `MD5|UnsaltedSHA1` · `AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]` · DRF login views without `throttle_classes`.
- **Java:** `\.unsecured\(\)|parseUnsecuredClaims` (jjwt 0.12) · `JWT\.decode\(` (auth0 java-jwt) without `JWT.require(..).build().verify` · `NoOpPasswordEncoder|MessageDigest\.getInstance\("(MD5|SHA-1)"\)` · resource server without `audiences` validation.
- **Go (golang-jwt v5):** `jwt\.Parse(WithClaims)?\(` without `jwt\.WithValidMethods` · `ParseUnverified\(` · a keyfunc that ignores `token.Method` · `insecure\.NewCredentials\(\)|grpc\.WithInsecure\(` between services.
- **PHP/Laravel:** login/reset/OTP routes without `throttle:` · `md5\(|sha1\(` on passwords · manual `==` comparison instead of `Hash::check`.
- **.NET:** `Validate(Issuer|Audience|Lifetime|IssuerSigningKey)\s*=\s*false` · `Require(SignedTokens|ExpirationTime)\s*=\s*false` · a custom `SignatureValidator\s*=`.
- **GraphQL / gRPC:** GraphQL login/OTP mutations reachable through batched arrays or aliases (one HTTP request, many attempts). gRPC: `add_insecure_port|ServerCredentials\.createInsecure\(\)` on non-loopback interfaces, or no auth interceptor.
- **False positives:** `decode` called *after* verification, or for display only; test fixtures; HS256 with a strong key from a secret store; limits enforced at the gateway or WAF (check that config).

### How to detect — runtime (safe, own app only)
- **Throttling:** send 20 wrong-password attempts for a test account. Expect 429, lockout or CAPTCHA before the 20th. Repeat for forgot-password, OTP verify and refresh.
- **GraphQL:** send a JSON array of 5 `login` operations (or 5 aliased `login` fields). They must be rejected or counted as 5 attempts.
- **Token handling:** each of these must return 401: an expired token, a tampered payload, an unsigned token (`alg: none`, empty signature), a token for another `aud`/`iss`, and an ID token used as an access token.
- **Logout/revocation:** after logout or a password change, reuse the old session/refresh token and expect 401. For stateless JWTs, confirm the access token lifetime is short.
- **Sensitive changes:** `PUT /account {"email":...}` with only a bearer token must demand the current password or step-up authentication.
- **Enumeration:** compare status, body and timing for an existing vs a non-existing user on login, register and reset.
- **Service-to-service:** call internal service ports directly in staging without credentials and expect 401.

### Tools
- **Semgrep** (rule IDs from github.com/semgrep/semgrep-rules; run with `semgrep scan --config r/<id-prefix>` or from a local clone): `javascript.jsonwebtoken.security.jwt-none-alg`, `javascript.jsonwebtoken.security.audit.jwt-decode-without-verify`, `javascript.jose.security.jwt-none-alg`, `python.jwt.security.unverified-jwt-decode`, `python.jwt.security.jwt-none-alg`, `java.jjwt.security.jwt-none-alg`, `java.java-jwt.security.audit.jwt-decode-without-verify`, `go.jwt-go.security.jwt-none-alg`, `go.jwt-go.security.audit.jwt-parse-unverified`, `csharp.lang.security.ad.jwt-tokenvalidationparameters-no-expiry-validation`. Also the packs `p/jwt`, `p/secrets`, `p/owasp-top-ten`.
- **CodeQL:** `js/jwt-missing-verification`, `java/missing-jwt-signature-check`, `go/missing-jwt-signature-check`, `js/insufficient-password-hash`, `js/missing-rate-limiting`.
- **Secret scanning:** `gitleaks git .` / `gitleaks dir .`, `trufflehog filesystem .`, Bandit B105/B106/B107, gosec G101.
- **Spectral OWASP** (on the OpenAPI spec): `owasp:api2:2023-no-http-basic`, `-no-api-keys-in-url`, `-no-credentials-in-url`, `-jwt-best-practices`, `-short-lived-access-tokens`, `-auth-insecure-schemes`, `-read-restricted`, `-write-restricted`.
- **DAST:** ZAP (`docker run zaproxy/zap-stable zap-api-scan.py -t http://host.docker.internal:8080/openapi.json -f openapi`), the Burp JWT Editor extension (token checks against your own app), graphql-cop (batching), and Schemathesis `--checks ignored_auth`.

### Fix / remediation
```js
// Node jsonwebtoken — bad: const claims = jwt.decode(token);
const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'],
  audience: 'orders-api', issuer: 'https://idp.example.com' });
```
```python
# PyJWT — good
claims = jwt.decode(token, key, algorithms=["RS256"], audience="orders-api",
                    issuer="https://idp.example.com", options={"require": ["exp", "iss", "aud"]})
```
```csharp
// ASP.NET Core — good
o.TokenValidationParameters = new() { ValidateIssuer = true, ValidateAudience = true,
  ValidateLifetime = true, ValidateIssuerSigningKey = true, ValidAlgorithms = new[] { "RS256" } };
```
More fixes:
- Use an IdP/OIDC or the framework's auth stack.
- Put a stricter limiter on login, reset and OTP, keyed by account and IP: `express-rate-limit`, `@nestjs/throttler` `@Throttle`, Laravel `RateLimiter::for('login', ...)`, DRF `ScopedRateThrottle`, ASP.NET `AddRateLimiter`.
- Hash passwords with Argon2id (m=19 MiB, t=2, p=1), bcrypt cost ≥ 10 (72-byte input limit), or PBKDF2-HMAC-SHA256 with 600,000 iterations.
- Require the current password before changing credentials, email or MFA, then revoke other sessions.
- Return generic auth errors.
- Use mTLS or short-lived signed tokens between services.
- Disable GraphQL batching, or count every operation in a batch toward the limit.

### Best-practice checklist (ASVS 5.0)
- [ ] Anti-automation for stuffing and brute force is documented and implemented (6.1.1, 6.3.1). OOB/OTP codes are rate-limited (6.6.3) and single-use (6.5.1).
- [ ] Passwords are ≥ 8 characters, 15 recommended (6.2.1); checked against the top 3000 and breached lists (6.2.4, 6.2.12); stored with an approved KDF (11.4.2).
- [ ] Password change requires the current password (6.2.3). Re-authenticate before email/phone/MFA changes (7.5.1). Offer "log out other sessions" (7.4.3).
- [ ] JWTs: signature verified (9.1.1); algorithm allowlist with no `none` (9.1.2); key sources pinned, with `jku`/`x5u`/`jwk` allowlisted (9.1.3); `exp`/`nbf` checked (9.2.1); token type (9.2.2) and `aud` (9.2.3) validated.
- [ ] A new session token is issued at login (7.2.4); logout invalidates it (7.4.1); no tokens or API keys in URLs (14.2.1).
- [ ] Service-to-service calls are authenticated with individual, short-lived credentials (13.2.1). Secrets live in a vault (13.3.1). No default accounts (6.3.2).
- [ ] All authentication events are logged (16.3.1).

### Severity guidance
- **Critical:** signature not verified, `alg:none` or forged tokens accepted; authentication bypass; signing secret committed to the repo; unauthenticated internal admin service.
- **High:** no brute-force/stuffing protection on login or OTP; email/phone change without re-auth (account-takeover chain); predictable or long-lived reset tokens; plaintext, MD5 or SHA-1 password storage.
- **Medium:** missing `aud`/`iss` checks; long-lived access tokens with no revocation; tokens in URLs; user enumeration.
- **Low:** weak password policy with compensating MFA; missing auth-event logging.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/ · https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html · https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- ASVS 5.0 V6/V7/V9/V11/V13/V14/V16 (github.com/OWASP/ASVS `5.0/en`) · npm jsonwebtoken 9.0.3 (`verify.js`, README)
- github.com/semgrep/semgrep-rules (cloned 2026-09) · github.com/github/codeql · github.com/gitleaks/gitleaks README · PyPI bandit 1.9.4

---
