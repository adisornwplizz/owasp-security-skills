## API6:2023 – Unrestricted Access to Sensitive Business Flows
**Edition notes:** New in 2023, with no 2019 equivalent. The release notes say it was created "to address new threats, including most of those that can be mitigated using rate limiting". API4:2023 covers technical resource exhaustion; API6 covers business harm from automated use that looks legitimate. The official page maps no CWEs and points to the OWASP Automated Threats (OAT) handbook.
**Maps to Top 10:2025: A06** (Insecure Design: CWE-799 and CWE-841 are mapped there, and A06 scenario #3 is scalper bots). Secondary: A01 (its prevention list includes "rate limits on API and controller access").

### What it is (issue)
An endpoint exposes a business flow that hurts the business when it is automated or used too much, and nothing restricts that use. Examples: buying limited stock (scalping), reserving every slot, spamming posts, farming referral or promo credit, and triggering paid SMS or email. Every single request is valid and authorized, so the harm comes from volume, speed or pattern rather than a code bug. Official ratings: Exploitability Easy, Prevalence Widespread, Detectability Average, Technical impact Moderate.

### Root causes
- Flows were never threat-modeled. Nobody asked "what hurts us if this gets scripted?", so no per-user or global business limits exist (ASVS 2.1.3).
- A generic per-IP request limit is treated as enough, and limits are not tied to a business identity such as account, device, payment instrument, phone or address.
- Anti-automation lives only in the web UI (a CAPTCHA widget). The same flow is reachable without it through the raw API, the mobile or partner API, an older version, GraphQL, or Next.js Server Actions.
- Rewards trigger on cheap events (signup) instead of qualifying ones (first paid order), with no caps, cooldowns or self-referral checks.
- Inventory logic checks and then acts without atomicity, so concurrent bots can oversell or double-book (ASVS 2.3.4).
- The client IP comes from a spoofable `X-Forwarded-For`, so per-IP limits reset on demand (ASVS 15.3.4).

### Key CWEs
The official page lists none. The closest fits:
- ★ CWE-799 Improper Control of Interaction Frequency (A06:2025)
- ★ CWE-837 Improper Enforcement of a Single, Unique Action (for example, one referral bonus per person)
- ★ CWE-841 Improper Enforcement of Behavioral Workflow (A06:2025)
- ★ CWE-770 Allocation of Resources Without Limits or Throttling
- ★ CWE-362 Race Condition, which causes overselling and double booking (A06:2025)
- ★ CWE-602 Client-Side Enforcement of Server-Side Security, such as a CAPTCHA that exists only in the UI (A06:2025)
- CWE-804 Guessable CAPTCHA

### How to detect — code review
- **Build a flow list.** Grep route names for `checkout|purchase|order|reserv|book|signup|register|referr|invite|coupon|promo|redeem|voucher|gift|withdraw|payout|transfer|vote|review|comment|otp|sms|send-?email`. For each flow, record whether it requires auth, what limit applies per user, device and globally, whether a CAPTCHA or attestation is verified server-side, and what business caps exist (quantity per order, orders per account per drop).
- **Find where limits live.** They may be in app middleware or in a gateway, WAF or CDN (NGINX `limit_req`, Kong, AWS WAF rate rules, API Gateway usage plans). Confirm that every entry point hits the same control: web, mobile, `/v1`, partner API, GraphQL, Server Actions, and queue consumers.
- **CAPTCHA smells.** The client uses `grecaptcha|turnstile|hcaptcha` but the server never calls `siteverify`. Or `success` is checked while `action`, `hostname` and (for reCAPTCHA v3) `score` are not. Or bypass flags exist, such as `if (isMobileApp) skip`.
- **Inventory and referral smells.** A read-modify-write such as `stock\s*-=\s*1|quantity\s*-\s*1` followed by `save()` outside a transaction or lock. No unique constraint on (user, promo_code). The bonus is credited inside the signup or register handler.
- **Node:** `express-rate-limit` is missing on flow routes, or `keyGenerator` is omitted so the key is IP only. `app.set\(['"]trust proxy['"],\s*true\)` trusts any XFF. NestJS: `@SkipThrottle\(` on flow controllers, or no `@Throttle\(` override. Next.js: `'use server'` files doing checkout or signup. Every Server Action is a public POST endpoint, so the limiter has to live inside the action.
- **Python:** DRF settings have no `DEFAULT_THROTTLE_CLASSES` or `throttle_scope`, or a view sets `throttle_classes\s*=\s*\[\]`. FastAPI and Flask: no `@limiter.limit\(` (slowapi or Flask-Limiter), or only `key_func=get_remote_address`.
- **Java/Spring:** no Bucket4j or Resilience4j `@RateLimiter` on flow controllers. The stock decrement has no `@Transactional` plus `@Lock(LockModeType.PESSIMISTIC_WRITE)`, and the entity has no `@Version`.
- **Go:** flow handlers are not wrapped by `rate.NewLimiter`, `httprate` or `tollbooth`, or the limiter map is keyed by `r.RemoteAddr` behind a proxy.
- **Laravel:** the route has no `throttle:` middleware. `RateLimiter::for(` uses only `->by($request->ip())`. Look for `withoutMiddleware\(.*throttle`.
- **.NET:** no `[EnableRateLimiting(` or `.RequireRateLimiting(`, or `[DisableRateLimiting]` on a flow. `ForwardedHeadersOptions` with `KnownProxies`/`KnownNetworks` cleared means it trusts every hop.
- **GraphQL:** `allowBatchedHttpRequests: true`, no alias or operation limits, or a limiter that counts HTTP requests. In that last case, N aliased `redeemCoupon` mutations in one POST count as a single request.
- **False positives:** limits enforced at the gateway, CDN or bot-management layer (confirm the config exists in IaC, not just in a claim). Partner or B2B APIs where automation is intended and controlled by keys, quotas and contracts. Public read-only catalog scraping, which is lower severity and closer to API4.

### How to detect — runtime (safe, own app only)
Run against staging with seeded data and test accounts, at low volume.
- **Velocity:** `for i in $(seq 20); do curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Authorization: Bearer $TEST_TOKEN" -H 'Content-Type: application/json' -d '{"code":"TEST"}' https://staging.example.com/api/coupons/redeem; done`. Expect 429 with `Retry-After` after the documented limit.
- **Key check:** repeat with `-H "X-Forwarded-For: 203.0.113.$i"`. The counter must not reset.
- **Channel parity:** run the same flow through the mobile, partner, older-version and GraphQL paths. The same limit must apply.
- **CAPTCHA:** send the protected request with a missing token, then with a garbage token. Expect 4xx. A token minted for a different `action` must also be rejected.
- **GraphQL batching:** send one POST containing 10 aliased mutations (`a1: redeem(code:"T"){ok} a2: ...`). Expect a rejection, or all 10 counted against the limit.
- **Race:** seed an item with stock=1, then fire 20 parallel purchases (`seq 20 | xargs -P20 -I{} curl ...`). Exactly one should succeed.
- **Referral:** two test accounts sharing the same device or payment test card should earn only one bonus.

### Tools
- No SAST tool reliably finds sensitive business flows in general. Rely on the flow inventory plus threat modeling with the OAT handbook: OAT-005 Scalping, OAT-017 Spamming, OAT-019 Account Creation, OAT-021 Denial of Inventory.
- Semgrep: `python/django/security/audit/django-rest-framework/missing-throttle-config.yaml`.
- Spectral with `@stoplight/spectral-owasp-ruleset` (`extends: ["@stoplight/spectral-owasp-ruleset"]`, then `spectral lint openapi.yaml`). Rules `owasp:api4:2023-rate-limit`, `-rate-limit-responses-429` and `-rate-limit-retry-after` enforce documented limits.
- GraphQL: GraphQL Armor (`@escape.tech/graphql-armor`) for max aliases, depth and cost. Apollo Server `allowBatchedHttpRequests` defaults to `false`.
- For low-rate verification on staging: k6, `oha` or `hey`. The defenses themselves (not scanners): Turnstile, reCAPTCHA or hCaptcha, and on mobile Play Integrity or App Attest.

### Fix / remediation
Put limits on each flow, keyed by identity (user plus device, payment instrument or phone), with a global cap per drop. Return 429.
```js
// Express — BAD: global per-IP limit only
app.use(rateLimit({ windowMs: 60_000, limit: 1000 }));
// GOOD: flow-specific, keyed to the account; trust exactly one proxy hop; CAPTCHA verified server-side
app.set("trust proxy", 1);
const checkoutLimiter = rateLimit({ windowMs: 10 * 60_000, limit: 3, keyGenerator: (req) => `co:${req.user.id}` });
app.post("/api/checkout", requireAuth, checkoutLimiter, verifyTurnstile("checkout"), checkout);
// verifyTurnstile: POST https://challenges.cloudflare.com/turnstile/v0/siteverify {secret, response, remoteip}
//   reject unless json.success && json.action === "checkout" && json.hostname === "shop.example.com"
//   (tokens are single-use and valid for 5 minutes)
```
```php
// Laravel — AppServiceProvider::boot()
RateLimiter::for('checkout', fn (Request $r) => [
    Limit::perMinute(3)->by('u:'.$r->user()->id),
    Limit::perDay(500)->by('drop:'.$r->input('drop_id')),   // global cap per product drop
]);
Route::post('/checkout', CheckoutController::class)->middleware(['auth:sanctum', 'throttle:checkout']);
```
```csharp
// ASP.NET Core — the default RejectionStatusCode is 503, so set 429 explicitly
builder.Services.AddRateLimiter(o => { o.RejectionStatusCode = 429;
  o.AddPolicy("checkout", ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.User.FindFirst("sub")?.Value ?? "anon",
      _ => new FixedWindowRateLimiterOptions { PermitLimit = 3, Window = TimeSpan.FromMinutes(10) })); });
app.UseRouting(); app.UseRateLimiter();   // must come after UseRouting for endpoint policies
app.MapPost("/api/checkout", Checkout).RequireAuthorization().RequireRateLimiting("checkout");
```
```sql
-- Atomic inventory. BAD: SELECT stock; if > 0 then UPDATE stock = :old - 1
UPDATE products SET stock = stock - 1 WHERE id = :id AND stock > 0;  -- GOOD: 1 row affected means reserved
```
Referrals: credit the bonus only after a qualifying action, cap it per referrer and period, allow one bonus per device, payment instrument and normalized email, and delay payouts. Flag patterns no human produces (add-to-cart to purchase in under 1 s) and alert on them (A09).

### Best-practice checklist
- [ ] Sensitive flows are inventoried, with business limits documented per user and globally (ASVS 2.1.3)
- [ ] Business limits are enforced as documented (ASVS 2.3.2), with anti-automation on costly or abusable functions (ASVS 2.4.1)
- [ ] High-value flows require realistic human timing (ASVS 2.4.2, L3), and steps cannot be skipped (ASVS 2.3.1)
- [ ] Limited resources are locked or decremented atomically, with no double booking (ASVS 2.3.4)
- [ ] Limits are keyed to authenticated identity or device, and the client IP comes only from trusted proxy hops (ASVS 15.3.4)
- [ ] CAPTCHA and attestation are verified server-side and bound to action and hostname; tokens are single-use
- [ ] Every channel and version (web, mobile, partner, GraphQL, old `/v1`) gets the same controls
- [ ] GraphQL batching is off, or limits count each operation; aliases are capped
- [ ] Machine-facing (B2B or developer) APIs require keys, quotas and contracts
- [ ] Flow velocity is monitored, with alerts on anomalies

### Severity guidance
- **Critical:** an automatable flow that turns directly into money with no limit (referral or promo credit that can be cashed out, payouts, gift-card balance checks), or unlimited paid SMS or voice sends (SMS pumping).
- **High:** a limited-inventory purchase or reservation flow with no identity-based limit or anti-automation; a CAPTCHA that is never verified server-side; a race that allows overselling.
- **Medium:** limits that are per-IP only and can be spoofed via XFF; limits on the web path only while mobile, GraphQL or an old version can bypass them; GraphQL aliases that multiply attempts.
- **Low:** limits that exist but are undocumented or unmonitored; low-impact spam where moderation already applies.

### Sources
- https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/ (raw: github.com/OWASP/API-Security/blob/master/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows.md)
- https://owasp.org/API-Security/editions/2023/en/0x04-release-notes/
- https://top10.owasp.org/2025/A06_2025-Insecure_Design/ (source: github.com/OWASP/Top10/blob/master/2025/docs/en/A06_2025-Insecure_Design.md)
- https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (V2 Validation and Business Logic, V15)
- https://owasp.org/www-project-automated-threats-to-web-applications/ (OAT-005, OAT-017, OAT-019, OAT-021 pages)
- https://cwe.mitre.org/data/definitions/837.html
- https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
- https://learn.microsoft.com/en-us/aspnet/core/performance/rate-limit and https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.ratelimiting.ratelimiteroptions.rejectionstatuscode
- https://express-rate-limit.mintlify.app/reference/configuration
- https://github.com/stoplightio/spectral-owasp-ruleset

---
