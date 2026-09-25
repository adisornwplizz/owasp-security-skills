## A07:2025 – Authentication Failures
**Edition notes:** Stays at #7, the same as 2021. Renamed from "Identification and Authentication Failures" (2021), which replaced 2017's "Broken Authentication" at #2; the official page calls it "a slight name change to more accurately reflect the 36 CWEs in this category". Mapped CWEs grew from 22 to 36, adding CWE-1390–1393 (weak and default credentials), CWE-306 (missing auth for critical function), CWE-308/309 (single-factor, password-only) and CWE-346 (origin validation). New emphasis: hybrid credential stuffing and password spray ("Winter2025" becomes "Winter2026"), weak MFA fallbacks, SSO sessions that single logout (SLO) doesn't end, and "for JWTs validate `aud`, `iss` claims and scopes". Stats: max incidence 15.80%, avg 2.92%, 1,120,673 occurrences, 7,147 CVEs.
- ⚠ The page's password-policy link points to NIST SP 800-63-3 §5.1.1, superseded by **SP 800-63B-4 (final, 26 Aug 2025)**, which is used below.
- ⚠ The page mislabels CWE-298 and CWE-299 as "…Host Mismatch". Their MITRE titles are "Improper Validation of Certificate Expiration" and "Improper Check for Certificate Revocation".

### What it is (issue)
The application can be tricked into treating an attacker as a legitimate user. This happens through credential guessing or stuffing with no anti-automation, default, weak or breached passwords, and broken recovery, MFA or step-up flows. It also happens when session identifiers are fixed, leaked, never rotated or never expired, or when tokens are accepted without checking issuer, audience, expiry and purpose. The impact ranges from single-account takeover to full admin compromise.

### Root causes
- Home-grown login, session, reset or MFA code instead of a vetted framework or IdP. Each hand-rolled step (compare, rotate, expire, invalidate) is a chance to get it wrong.
- Rate limiting and anti-automation were never designed in, or were applied per account only. That per-account limit doesn't stop password spray across many accounts or stuffing from many IPs.
- Multiple auth pathways (web, mobile API, legacy `/v1`, admin, OAuth callback, "remember me") with inconsistent controls, so an alternate path bypasses MFA or throttling (CWE-288).
- Stateless JWT sessions adopted without a revocation or expiry design, so logout and password reset don't end access.
- JWT or OIDC libraries used with lax options (decode-only, no `aud`/`iss`, `ignoreExpiration`) because the defaults were never reviewed.
- Legacy password rules (composition, rotation, short minimum, blocked paste) that push users toward predictable passwords. No blocklist or breached-password check.
- Recovery treated as a UX feature, not an auth path: predictable, long-lived, reusable reset tokens, links built from the `Host` header, KBA "secret questions".
- Seed or demo accounts and default credentials that survive into production. Trust in IP, `Referer` or a client-set header as proof of identity.

### Key CWEs
Official mapping (36): CWE-258, 259, 287, 288, 289, 290, 291, 293, 294, 295, 297, 298, 299, 300, 302, 303, 304, 305, 306, 307, 308, 309, 346, 350, 384, 521, 613, 620, 640, 798, 940, 941, 1390, 1391, 1392, 1393. The ★ entries matter most for web/API developers:
- ★ CWE-287 Improper Authentication (JWT claims not validated, broken custom auth)
- ★ CWE-306 Missing Authentication for Critical Function
- ★ CWE-307 Improper Restriction of Excessive Authentication Attempts (no rate limit or lockout, OTP brute force)
- ★ CWE-384 Session Fixation
- ★ CWE-613 Insufficient Session Expiration (no idle or absolute timeout, logout doesn't invalidate)
- ★ CWE-640 Weak Password Recovery Mechanism for Forgotten Password
- ★ CWE-798 Use of Hard-coded Credentials (with CWE-259 and CWE-1392/1393 default credentials or password)
- ★ CWE-521 Weak Password Requirements (with CWE-1391 Use of Weak Credentials)
- Also check: CWE-288 Authentication Bypass Using an Alternate Path or Channel, CWE-620 Unverified Password Change, CWE-308 Use of Single-factor Authentication, CWE-294 Authentication Bypass by Capture-replay, CWE-290/291/293 (spoofing, IP-based or Referer-based auth), CWE-295/297 certificate validation (patterns are in A04).

### How to detect — code review
**Stack-agnostic signals.** Start by listing every auth entry point: login, register, forgot/reset, MFA enroll and verify, OAuth/OIDC callback, token refresh, API-key auth, admin login, and mobile or legacy routes. Then check each one for the following.
- **Throttling:** middleware on login, OTP-verify and reset endpoints, keyed by account *and* IP/device, plus global anomaly detection.
- **Uniform failure behavior:** the same message, status and response size, and roughly equal timing (a dummy hash when the user doesn't exist). Registration and forgot-password must behave the same way.
- **Session lifecycle:** new ID on login, re-auth and privilege change; server-side destroy on logout; idle and absolute timeouts; cookie flags `Secure`, `HttpOnly`, `SameSite` with a `__Host-` prefix; never in a URL, a hidden field or `localStorage`.
- **Token verification:** signature with a pinned `alg`; `exp`/`nbf`, `iss`, `aud`; token type or purpose (an ID token is not an access token); refresh-token rotation or sender-constraining, and revocation on logout or reset.
- **Recovery:** CSPRNG token of ≥128 bits stored hashed; short expiry and single use; link built from configured `APP_URL`, never from `Host`; sessions revoked after reset; MFA not bypassed (ASVS 6.4.3); no KBA.
- **Password change:** requires the current password (CWE-620). Changes to email, phone or MFA require re-auth (ASVS 7.5.1).
- **MFA:** enforced on every pathway. OTPs single-use, rate-limited and short-lived: out-of-band codes ≤10 min, TOTP ≤30 s (ASVS 6.5.5). SMS is not the only option.
- **Credentials in code:** seeds, migrations, `docker-compose`, Helm values or README with `admin/admin`, `changeme`, `password`. Auth decided by `X-Forwarded-For`, `Referer` or a custom `X-User-Id` header.
- **OAuth/OIDC client:** `state`, `nonce` and PKCE `S256` generated per transaction and bound to the session. Callback rejects mismatches. No implicit or ROPC grants. On your own authorization server: exact-match `redirect_uri` (RFC 9700).

**Node (Express/NestJS/Next.js)**
```
rg -n "req\.session\.(user|userId|uid)\s*=" ; rg -n "session\.regenerate\(|req\.login\("   # no regenerate/passport<0.6 = fixation
rg -n "session\.destroy\(|req\.logout\(" ; rg -n "cookie:\s*\{[^}]*(secure:\s*false|httpOnly:\s*false|sameSite:\s*['\"]none)"
rg -n "jwt\.verify\(" | rg -v "algorithms"          # also check audience/issuer/maxAge options
rg -n "jwt\.decode\(|ignoreExpiration:\s*true|clockTolerance:\s*\d{4,}"
rg -n "express-rate-limit|@nestjs/throttler|@Throttle\(|rateLimit\(" ; rg -in "user not found|incorrect password|no account"
rg -n "localStorage\.setItem\([^)]*(token|jwt|refresh)" ; rg -n "maxAge:\s*\d{7,}" # Auth.js default session maxAge = 30 days
```
**Python (Django/FastAPI/Flask)**
```
rg -n "request\.session\[['\"](user|user_id|uid)['\"]\]\s*=" ; rg -n "cycle_key\(|login\(request"
rg -n "AUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\]|min_length['\"]?\s*[:=]\s*[0-7]\b"
rg -n "SESSION_COOKIE_AGE|SESSION_COOKIE_SECURE\s*=\s*False|PERMANENT_SESSION_LIFETIME|https_only\s*=\s*False"
rg -n "jwt\.decode\(" | rg -v "audience" ; rg -n "verify_(exp|aud|iss|signature)['\"]:\s*False"
rg -n "django-axes|django_ratelimit|slowapi|flask_limiter|@limiter\.limit"   # absence on login/OTP
```
**Java (Spring Boot)**
```
rg -n "sessionFixation\(\)\.none\(\)|sessionFixation\(\s*\w*\s*->\s*\w*\.none\(\)\)"
rg -n "\{noop\}|withDefaultPasswordEncoder\(\)|rememberMe\([^)]*\)\.key\(\""
rg -n "parseUnsecuredClaims|parseClaimsJwt\(|\.setSigningKey\(\"|JWT\.decode\("   # jjwt / java-jwt decode-only
rg -n "resourceserver\.jwt" application*.yml application*.properties   # issuer-uri set? audiences set? (aud NOT validated by default)
rg -n "server\.servlet\.session\.(timeout|cookie\.(secure|http-only))"
```
**Go**
```
rg -n "jwt\.Parse(WithClaims)?\(" | rg -v "WithValidMethods"
rg -n "ParseUnverified|WithoutClaimsValidation" ; rg -n "WithAudience|WithIssuer|WithExpirationRequired"   # exp only checked if present
rg -n "http\.Cookie\{" -A6 | rg -v "Secure:\s*true|HttpOnly:\s*true" ; rg -n "sessions\.NewCookieStore\(\[\]byte\(\""
rg -n "RenewToken\(" ; rg -n "(password|apiKey|token)\s*==\s*" -i   # use subtle.ConstantTimeCompare / bcrypt compare
```
**PHP (Laravel)**
```
rg -n "Auth::attempt\(" -A6 | rg "regenerate\(" ; rg -n "Auth::logout\(\)" -A4 | rg "invalidate\(\)"
rg -n "throttle:|RateLimiter::for\(" routes/ app/Providers
rg -n "SESSION_(LIFETIME|SECURE_COOKIE|SAME_SITE)" .env* config/session.php   # secure defaults to env (null)
rg -n "Password::(min|defaults)\(" ; rg -n "uncompromised\(\)"
rg -n "==\s*\\\$request->(input|get|header)\(['\"](token|api_key|password|secret)"   # use hash_equals()
```
**.NET (ASP.NET Core)**
```
rg -n "lockoutOnFailure:\s*false"                              # Identity template default
rg -n "Validate(Audience|Issuer|Lifetime|IssuerSigningKey)\s*=\s*false|Require(ExpirationTime|SignedTokens)\s*=\s*false|SignatureValidator\s*="
rg -n "ClockSkew\s*=\s*TimeSpan\.From(Hours|Days)|ExpireTimeSpan\s*=\s*TimeSpan\.FromDays"
rg -n "RequiredLength\s*=\s*[0-7]\b|Require(Digit|Uppercase|NonAlphanumeric)\s*=\s*true"  # composition rules conflict with NIST
rg -n "CookieSecurePolicy\.(None|SameAsRequest)|HttpOnly\s*=\s*(false|HttpOnlyPolicy\.None)"
```
**Insecure framework defaults to flag** (verified from source or docs):

| Framework | Default | Problem |
|---|---|---|
| Django | `SESSION_COOKIE_SECURE=False`, `SESSION_COOKIE_AGE`=2 weeks | Cookie sent over HTTP; long-lived session |
| Flask | `SESSION_COOKIE_SECURE=False`, `PERMANENT_SESSION_LIFETIME`=31 days | Signed client-side cookie, so it can't be revoked server-side |
| Starlette `SessionMiddleware` | `https_only=False`, `max_age`=14 days | Cookie sent over HTTP; long-lived session |
| express-session | `cookie.secure` false | Cookie sent over HTTP |
| Laravel | `secure` from `SESSION_SECURE_COOKIE` (unset), `SESSION_LIFETIME`=120 min | Secure flag off unless the env var is set |
| Auth.js | session `maxAge` 30 days | Long-lived session |
| ASP.NET Identity | `RequiredLength=6` plus composition rules; lockout 5 attempts/5 min only when `lockoutOnFailure: true` | Policy contradicts NIST; lockout off in templates |
| Spring resource server | validates `exp`/`nbf` and `iss` (when `issuer-uri` is set); RS256-only by default | **`aud` is not validated** unless `audiences` or a validator is configured |

**False-positive notes**
- These frameworks already rotate the session ID on login: Django `login()` (`cycle_key`), Spring Security (default `changeSessionId`), Passport ≥0.6 `req.login()`, Laravel `SessionGuard::login()` (migrates the session; docs still show `session()->regenerate()`), and ASP.NET cookie `SignInAsync`. Flag fixation only for custom session writes or explicit opt-outs.
- Throttling, bot defense or MFA may live at the gateway, WAF or IdP (Cloudflare, API Gateway, Auth0/Cognito/Entra). Check infra config and IdP settings before reporting "no rate limiting".
- `jwt.verify(token, publicKey)` without `algorithms` in jsonwebtoken v9 infers allowed algorithms from the key type. That is lower risk, but still recommend pinning.
- Stateless access tokens that survive logout are acceptable when short-lived (minutes) and refresh tokens are revoked server-side. Note it against ASVS 7.4.1 rather than as a High.
- "Email already registered" on sign-up can be a product decision. Mitigate with rate limits and CAPTCHA, and send the result by email. Non-enumeration is ASVS 6.3.8 at L3; the Top 10 still recommends identical messages.
- Default credentials in test fixtures or local-only seeders are fine if they can't run in prod (check `APP_ENV` guards and deploy scripts).

### How to detect — runtime (safe, own app only)
Use only test accounts you own on localhost or staging. Keep request counts small.
- **Enumeration:** compare an existing and a non-existing account:
  ```
  for e in me@test.local nobody-$RANDOM@test.local; do curl -s -o /dev/null -w "%{http_code} %{size_download} %{time_total}\n" -X POST http://localhost:3000/api/login -H 'content-type: application/json' -d "{\"email\":\"$e\",\"password\":\"Wrong-Password-12345\"}"; done
  ```
  Status, size and message should be identical and timing similar. Repeat for `/forgot-password` and `/register`.
- **Throttling:** send about 25 wrong passwords to *your* test account, then collect the status codes with `… | sort | uniq -c`. Expect 429 responses, progressive delay or a temporary lock. Then confirm the account recovers, so an attacker can't lock users out as a DoS. Repeat on the OTP-verify and reset-code endpoints.
- **Session fixation:** `curl -c jar -b jar https://localhost/login` and note the session cookie, then log in using the same jar. The session cookie value **must change**.
- **Logout and reset invalidation:** save the cookie or refresh token, log out (or reset the password), then replay with `curl -b "sid=<old>" https://localhost/api/me`. Expect 401 or a redirect.
- **Timeouts:** inspect `Set-Cookie` `Max-Age`/`Expires`, decode the JWT (`exp - iat`), and check the configured idle and absolute timeouts. Staging with shortened timeouts can prove server-side enforcement.
- **Token validation:** mint test tokens with your dev IdP or dev signing key: expired, wrong `aud`, wrong `iss`, an ID token sent as an access token, and a refresh token sent as an access token. All should return 401.
- **Password policy:** a 7-character password and a common one such as `123456789012345` are rejected; a 64+ character, Unicode or pasted password is accepted; a password change without the current password is rejected.
- **Reset flow:** reused and expired tokens are rejected; other sessions end after the reset. Send a reset request with a `Host: example.invalid` header and check the email in Mailpit: it must still link to the canonical domain.
- **MFA:** replaying a just-used TOTP is rejected; every pathway (API, mobile, legacy) demands MFA; disabling MFA requires re-authentication.
- **OAuth/OIDC client:** the authorize URL carries `state`, `nonce` (for OIDC), `code_challenge` and `code_challenge_method=S256`. A callback with a modified `state` is rejected. On your own authorization server, a registered `redirect_uri` with an extra path or query is rejected.
- **Default accounts:** confirm staging has no `admin/admin`-style or seeded demo users.

### Tools
- **ZAP baseline (passive):** `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example.com`. Relevant alerts: 10010 Cookie No HttpOnly Flag, 10011 Cookie Without Secure Flag, 10054 Cookie without SameSite, 3 Session ID in URL Rewrite, 10105 Weak Authentication Method, 10111/10112 Authentication Request and Session Management Response identified. Active rule 40013 Session Fixation only against your own staging.
- **Semgrep:** `semgrep scan --config p/jwt --config p/secrets --config p/owasp-top-ten`. Rules (full ID = file path + rule id):
  - `javascript.jsonwebtoken.security.audit.jwt-decode-without-verify.jwt-decode-without-verify`, `javascript.express.security.audit.express-jwt-not-revoked.express-jwt-not-revoked`
  - `javascript.express.security.audit.express-session-hardcoded-secret.express-session-hardcoded-secret`, `javascript.express.security.audit.express-cookie-settings.express-cookie-session-no-secure`
  - `go.jwt-go.security.audit.jwt-parse-unverified.jwt-go-parse-unverified`, `python.django.security.audit.unvalidated-password.unvalidated-password`
  - `csharp.lang.security.ad.jwt-tokenvalidationparameters-no-expiry-validation.jwt-tokenvalidationparameters-no-expiry-validation`
  - `php.laravel.security.laravel-cookie-secure-set.laravel-cookie-secure-set`, `typescript.react.security.audit.react-jwt-in-localstorage.react-jwt-in-localstorage`
- **Hard-coded or default credentials (CWE-259/798):** `gitleaks git .`, `trufflehog git file://. --results=verified,unknown`, Bandit `-t B105,B106,B107`, gosec `-include=G101`, Find Security Bugs `HARD_CODE_PASSWORD`.
- **.NET analyzers:** CA5404 (token validation checks disabled), CA5382/CA5383 (secure cookies).
- **Manual flow testing:** ZAP or Burp against your own app, plus Mailpit/MailHog to read reset and verification emails. Use the HIBP Pwned Passwords range API (`https://api.pwnedpasswords.com/range/<5-hex SHA-1 prefix>`, k-anonymity, no API key) for breached-password checks in-app.

### Fix / remediation
**Session: rotate on login, destroy on logout, harden the cookie**
```js
// Express BAD: req.session.userId = user.id;   (same pre-login session ID)
app.use(session({ secret: process.env.SESSION_SECRET, name: '__Host-sid', resave: false, saveUninitialized: false,
  cookie: { secure: true, httpOnly: true, sameSite: 'lax', path: '/', maxAge: 30 * 60e3 }, rolling: true })); // 30-min idle
// rolling = idle timeout only; enforce an absolute limit too, e.g. reject if Date.now() - req.session.createdAt > 8h
app.post('/login', loginLimiter, async (req, res, next) => {
  const user = await verifyCredentials(req.body);            // generic failure + dummy hash inside
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });
  req.session.regenerate(err => { if (err) return next(err);
    req.session.userId = user.id; req.session.createdAt = Date.now(); req.session.save(() => res.sendStatus(204)); });
});
app.post('/logout', (req, res) => req.session.destroy(() =>
  res.clearCookie('__Host-sid', { path: '/', secure: true, httpOnly: true, sameSite: 'lax' }).sendStatus(204)));
```
```php
// Laravel: after Auth::attempt(...)            // logout
$request->session()->regenerate();              Auth::logout(); $request->session()->invalidate(); $request->session()->regenerateToken();
// .env: SESSION_SECURE_COOKIE=true  SESSION_SAME_SITE=lax ; route: ->middleware('throttle:login')
RateLimiter::for('login', fn (Request $r) => [Limit::perMinute(5)->by(Str::lower($r->input('email')).'|'.$r->ip()), Limit::perMinute(50)->by($r->ip())]);
```
**Generic errors and equal timing** (Node; the same idea applies in any stack)
```js
const user = await db.user.findUnique({ where: { email } });
const ok = await argon2.verify(user?.passwordHash ?? DUMMY_ARGON2ID_HASH, password) && !!user;  // no early return
if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
```
**JWT and access-token validation: pin alg, require exp, check iss/aud/type**
```js
// Node BAD: jwt.decode(t)  |  jwt.verify(t, key)  |  { ignoreExpiration: true }
const claims = jwt.verify(t, publicKey, { algorithms: ['RS256'], issuer: 'https://idp.example.com/', audience: 'api://orders', maxAge: '15m' });
```
```python
# PyJWT BAD: jwt.decode(t, options={"verify_signature": False})
claims = jwt.decode(t, key, algorithms=["RS256"], audience="api://orders", issuer="https://idp.example.com/",
                    options={"require": ["exp", "iat", "sub"]})
```
```go
tok, err := jwt.Parse(s, keyFunc, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(iss),
    jwt.WithAudience("api://orders"), jwt.WithExpirationRequired())   // exp is optional unless required
```
- .NET: set `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`, `ValidateIssuerSigningKey`, `RequireExpirationTime` and `RequireSignedTokens` to true, `ValidAlgorithms = [SecurityAlgorithms.RsaSha256]`, and a small `ClockSkew` (default 5 min). Spring: set `spring.security.oauth2.resourceserver.jwt.audiences`.
- Keep access tokens short-lived (minutes). Rotate refresh tokens and revoke them on logout or password reset; for public clients RFC 9700 requires rotation or sender-constraining (DPoP/mTLS).
- For JWT "logout", use a `jti` denylist, a per-user "tokens valid after" timestamp, or per-user key rotation (ASVS 7.4.1). Keep tokens out of `localStorage`; prefer HttpOnly cookies or a backend-for-frontend (ASVS 10.1.1).

**Password policy** (NIST SP 800-63B-4 plus ASVS 6.2)
- Minimum **15** characters when the password is the only factor, or **8** when MFA is enforced. Allow **at least 64**. No composition rules and no periodic rotation; force a change only on evidence of compromise.
- Check new passwords against a blocklist (common, context-specific such as app or company name, and breached). Allow paste and password managers. No hints and no KBA.
- Never truncate or case-fold. Watch bcrypt's 72-byte limit: reject rather than silently truncate.
- Framework support: Laravel `Password::min(15)->uncompromised()`; Django `MinimumLengthValidator` with `min_length` 15 plus `CommonPasswordValidator` (a 20k list); ASP.NET `RequiredLength=15` with the `Require*` composition flags off.

**Brute force and stuffing**
- Layer the defenses: a per-account limit with exponential backoff, a per-IP and per-ASN limit, a global anomaly alert, CAPTCHA only after failures, and MFA (preferring phishing-resistant WebAuthn/passkeys).
- NIST: at most **100** consecutive failed attempts per authenticator before disabling it; stricter limits are allowed.
- ASP.NET Identity: `PasswordSignInAsync(..., lockoutOnFailure: true)`. Django `django-axes`, FastAPI `slowapi`, Flask `Flask-Limiter`, Express `express-rate-limit`, NestJS `@nestjs/throttler`.

**Password reset**
- Generate the token as `secrets.token_urlsafe(32)` or `crypto.randomBytes(32)`. Store `sha256(token)` with `user_id`, `expires_at` (short: minutes to an hour) and `used_at`; invalidate it on use and on any new request.
- Build the URL from configured `APP_URL`, never from the `Host` header. Send `Referrer-Policy: no-referrer` on the reset page.
- Don't auto-login after the reset. Revoke sessions, notify the user, and require MFA if enrolled.

**OAuth/OIDC client**
- Use a certified library (openid-client, Authlib, Spring Security OAuth2 Client, Microsoft.Identity.Web) with the authorization code flow plus **PKCE S256** (RFC 9700: mandatory for public clients, recommended for confidential ones).
- Generate `state` and OIDC `nonce` per transaction and bind them to the session. Validate the ID token's `aud == client_id`, `iss`, `exp` and `nonce`, and identify users by `iss`+`sub`, not by email (ASVS 6.8.1, 10.5.2).
- No implicit or ROPC grants. On your own authorization server: exact-string `redirect_uri` matching and one-time codes that live ≤10 min.

### Best-practice checklist
- [ ] Anti-automation (rate limit, backoff, alerting) is documented and implemented for login, OTP and reset (ASVS 6.1.1, 6.3.1). The per-authenticator lockout is ≤100 attempts (NIST).
- [ ] MFA is available and enforced for sensitive or all users, on every auth pathway, with no undocumented paths (6.3.3, 6.3.4). PSTN/SMS is not the only option (6.6.1).
- [ ] Password min 8 (15 strongly recommended, and required by NIST when single-factor) (6.2.1). ≥64 characters allowed (6.2.9). No composition rules (6.2.5). Paste and managers allowed (6.2.7). No truncation (6.2.8). No forced rotation (6.2.10).
- [ ] Top-3000 or larger common-password list (6.2.4). Context words (6.2.11). Breached-password check (6.2.12).
- [ ] No default accounts (6.3.2). No hard-coded or seeded credentials in deployable code or images.
- [ ] Identical responses (and roughly equal timing) for unknown user or bad password on login, register and reset (6.3.8, L3; the Top 10 recommends it for all).
- [ ] Password change requires the current password (6.2.3). Email, phone and MFA changes require re-auth (7.5.1). The user is notified of credential changes (6.3.7).
- [ ] Reset: CSPRNG, single-use, short-lived, hashed at rest. Doesn't bypass MFA (6.4.3). No hints or KBA (6.4.2). Initial or activation secrets expire (6.4.1).
- [ ] OTP and lookup secrets are single-use (6.5.1) and CSPRNG-generated (6.5.3). Out-of-band ≤10 min, TOTP ≤30 s (6.5.5). Code-based out-of-band flows are rate-limited (6.6.3).
- [ ] Session tokens: CSPRNG with ≥128 bits (7.2.3). New token on authentication (7.2.4). Idle and absolute timeouts set (7.3.1, 7.3.2) and aligned with NIST: AAL2 idle ≤1 h and overall ≤24 h; AAL3 15 min / 12 h.
- [ ] Logout and expiry actually terminate the session or token server-side (7.4.1). Sessions are killed when the account is disabled (7.4.2). Option to end other sessions after a credential change (7.4.3).
- [ ] Cookies are `Secure` with a `__Host-`/`__Secure-` prefix (3.3.1), `HttpOnly` (3.3.4) and have an appropriate `SameSite` (3.3.2). Tokens never appear in URLs (14.2.1).
- [ ] Self-contained tokens: `exp`/`nbf` checked (9.2.1), correct token type (9.2.2), `aud` allowlisted (9.2.3). Resource server checks `aud` and scopes (10.3.1, 10.3.2).
- [ ] OAuth client: PKCE or `state` for CSRF (10.2.1). `state`, `nonce` and verifier bound to the user-agent session (10.1.2). ID token `nonce` (10.5.1) and `aud == client_id` (10.5.4) checked.
- [ ] Your own authorization server: exact `redirect_uri` match (10.4.1), PKCE required (10.4.6), no implicit or password grant (10.4.4), code lifetime ≤10 min (10.4.3), absolute refresh-token expiry (10.4.8).

### Severity guidance
- **Critical:** an authentication bypass reachable by an unauthenticated attacker: a missing auth check on an admin or critical endpoint (CWE-306), JWT signature or claims not verified (forged tokens accepted), or an alternate path skipping auth or MFA (CWE-288). Also default or hard-coded admin credentials in prod; a reset token that is predictable, returned in the API response, or reusable indefinitely; and wildcard `redirect_uri` matching on your own authorization server, which leaks codes or tokens.
- **High:** no throttling on login or OTP verification (especially a 6-digit OTP); session fixation; sessions or refresh tokens that survive logout or a password reset; access tokens without `exp`, or valid for days with no revocation; `aud`/`iss` not checked where tokens from the same IdP serve several apps; a public OAuth client without PKCE or `state`; password change without the current password; reset links built from the `Host` header; an MFA fallback weaker than the primary factor.
- **Medium:** user enumeration by message, status or timing; minimum length <8, or no blocklist or breached check; excessive session lifetime or no idle timeout (e.g., framework defaults of 14–31 days on a sensitive app); cookies missing `Secure`/`HttpOnly`/`SameSite`; tokens in `localStorage`; SMS as the only MFA option; no re-auth for email or MFA changes.
- **Low:** forced composition or rotation rules (contrary to NIST); maximum length <64, or paste blocked; no notification on credential changes; no UI to view or terminate sessions; missing logout link; minimum length of 8–14 on a single-factor app, where NIST 800-63B-4 requires 15.

### Sources
- https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/ (served from top10.owasp.org)
- https://owasp.org/Top10/2021/A07_2021-Identification_and_Authentication_Failures/
- https://pages.nist.gov/800-63-4/sp800-63b.html (SP 800-63B-4, final 26 Aug 2025) ; https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf
- https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html ; https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html ; https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
- https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (V3.3, V6, V7, V9, V10)
- https://www.rfc-editor.org/rfc/rfc9700.html (OAuth 2.0 Security BCP, Jan 2025) ; https://oauth.net/2/oauth-best-practice/
- https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/ (JWT BCP update, -10, RFC Editor queue)
- https://cwe.mitre.org/data/definitions/298.html ; https://cwe.mitre.org/data/definitions/1390.html
- https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html ; https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration
- https://docs.djangoproject.com/en/6.0/topics/auth/passwords/ ; https://github.com/django/django (global_settings.py)
- https://github.com/pallets/flask (app.py defaults) ; https://github.com/encode/starlette (middleware/sessions.py)
- https://github.com/laravel/framework/blob/13.x/config/session.php ; https://laravel.com/docs/12.x/hashing
- https://authjs.dev/reference/core#session
- https://medium.com/passportjs/fixing-session-fixation-b2b68619c51d (Passport 0.6 regenerates session)
- https://pkg.go.dev/github.com/golang-jwt/jwt/v5 ; https://github.com/golang-jwt/jwt (validator.go)
- https://pyjwt.readthedocs.io/en/stable/changelog.html ; https://haveibeenpwned.com/API/v3#PwnedPasswords
- https://www.zaproxy.org/docs/alerts/ ; https://github.com/semgrep/semgrep-rules ; https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings
