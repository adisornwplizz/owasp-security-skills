## A06:2025 – Insecure Design
**Edition notes:** Was A04:2021 (#4, new in 2021); slides to **#6** in 2025 as A02:2025 Security Misconfiguration and A03:2025 Software Supply Chain Failures leapfrog it. OWASP credits industry improvement in threat modeling and secure-design emphasis. 39 CWEs mapped (40 in 2021). Newly mapped: CWE-286, **362 (race condition)**, 382, 436, 454, 628, 676, 693, 1022, 1125. No longer here: CWE-209/235/280 (now in A10:2025 Mishandling of Exceptional Conditions), 213, 257, 430, 579, 650, 840 (Business Logic Errors category), 927, 1173. 2025 prevention list adds "segregate tenants robustly by design throughout all tiers". Stats: max incidence 22.18%, avg 1.86%, 729,882 occurrences, 7,647 CVEs. API counterparts: **API6:2023 Unrestricted Access to Sensitive Business Flows**, **API4:2023 Unrestricted Resource Consumption**; overlaps A01 (tenant isolation), A07 (recovery flows), API3:2023 (mass assignment).

### What it is (issue)
"Missing or ineffective control design": the needed security control was never specified, so no amount of perfect implementation can fix it (as opposed to an implementation defect in a sound design). In code it shows up as business logic the server does not enforce: client-trusted prices, skippable workflow steps, check-then-act races on money/inventory/coupons, no limits on costly or valuable flows, non-idempotent payment operations, and implicit trust boundaries. Scanners rarely find it; reviewers find it by asking "what if a user does this out of order, twice, concurrently, at scale, or with a value the UI never sends?"

### Root causes
- No threat modeling or abuse cases; requirements capture only the happy path; no documented business limits (ASVS 2.1.3).
- Server trusts client-held state: price/total/discount/role/step/status in body, hidden fields, cookies, localStorage (CWE-602, 472, 642).
- Implicit trust boundaries: internal services, gateway-set headers (`X-User-Id`, `X-Forwarded-For`), webhooks assumed authentic (CWE-501, 807).
- Check-then-act on shared state without atomicity; in-process locks (`synchronized`, `lock`, JS `Map`) in multi-instance deployments; "Node is single-threaded" myth—every `await` between check and write is a race window (CWE-362).
- Multi-step flows built as independent endpoints with no server-side state machine (CWE-841).
- No per-user/global quotas, velocity limits or anti-automation on valuable flows (OTP/SMS, signup, referral, coupon, checkout, LLM calls) (CWE-799).
- Operations not idempotent although clients, proxies and webhook senders retry.
- Tenant scoping left to each individual query instead of enforced centrally (CWE-653).
- Weak recovery designs (security questions), security through obscurity (CWE-656), excessive attack surface (CWE-1125).
- Tests cover features, not misuse; no negative/concurrency tests for critical flows.

### Key CWEs
Full list (39): 73, 183, 256, 266, 269, 286, 311, 312, 313, 316, 362, 382, 419, 434, 436, 444, 451, 454, 472, 501, 522, 525, 539, 598, 602, 628, 642, 646, 653, 656, 657, 676, 693, 799, 807, 841, 1021, 1022, 1125. ★ = most relevant for web/API devs.
- ★ CWE-362 Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')
- ★ CWE-841 Improper Enforcement of Behavioral Workflow
- ★ CWE-602 Client-Side Enforcement of Server-Side Security
- ★ CWE-472 External Control of Assumed-Immutable Web Parameter; CWE-642 External Control of Critical State Data
- ★ CWE-799 Improper Control of Interaction Frequency
- ★ CWE-807 Reliance on Untrusted Inputs in a Security Decision; ★ CWE-501 Trust Boundary Violation
- ★ CWE-434 Unrestricted Upload of File with Dangerous Type; CWE-646 Reliance on File Name or Extension of Externally-Supplied File
- CWE-653 Insufficient Compartmentalization; CWE-657 Violation of Secure Design Principles; CWE-1125 Excessive Attack Surface
- CWE-522 Insufficiently Protected Credentials; CWE-256 Unprotected Storage of Credentials; CWE-598 Use of GET Request Method With Sensitive Query Strings; CWE-1021 Improper Restriction of Rendered UI Layers or Frames; CWE-1022 window.opener; CWE-444 HTTP Request Smuggling

### How to detect — code review
**Method: how a code reviewer spots design flaws**
1. **Inventory sensitive flows**: money, credits/points, inventory/seats, coupons/gift cards/referrals, OTP/SMS/email sends, signup/invite, password reset, approvals, exports, paid third-party/LLM calls. `rg -n -i -l 'coupon|voucher|gift.?card|promo|referral|withdraw|transfer|payout|refund|balance|credit|wallet|checkout|order|inventory|stock|seat|booking|otp|verify|reset|invite'`
2. **Source of truth**: for each flow, list what the client sends vs what the server recomputes from its own data. Anything security- or money-relevant taken from the request is a finding unless re-derived or bounded.
3. **State machine**: does each step load server-side state and check the precondition (`status == 'pending_payment'`) before transitioning? Can steps be skipped, repeated, reordered, or called after cancel?
4. **Concurrency**: is check + write one atomic operation (conditional UPDATE, row lock, unique constraint, optimistic version)?
5. **Limits & automation**: per-user, per-resource and global limits; rate limits keyed on something not spoofable (ASVS 15.3.4).
6. **Idempotency & replay**: retries, double-clicks, webhook redelivery.
7. **Trust boundaries**: which inputs cross a boundary (browser, partner, webhook, header from proxy, LLM output) and where they're validated.

**Stack-agnostic smells (grep then read)**
```
# client-supplied money/role/state fields in request handling
rg -nP -i '(body|data|json|form|input|params|request)\W{1,3}\w*\W{0,3}(price|unit_?price|amount|total|subtotal|discount|fee|tax|currency|balance|credits?|points|role|is_?admin|status|approved|verified|step)\b'
# hidden fields carrying state
rg -nP -i 'type=["\x27]hidden["\x27][^>]*name=["\x27](price|amount|total|discount|role|user_?id|status|step)'
# security decisions on spoofable headers
rg -n -i 'x-user-id|x-tenant|x-role|x-forwarded-for|x-real-ip|x-original-url'
# flows with money/limited resources but no locking/atomic primitives (list files, then read)
rg -l -i 'coupon|voucher|withdraw|transfer|redeem|balance|stock|inventory' | xargs rg -L -i 'for update|select_for_update|lockForUpdate|PESSIMISTIC|@Version|ConcurrencyCheck|Timestamp\]|rowversion|\$transaction|transaction\.atomic|DB::transaction|@Transactional|BeginTx|isolation'
# recovery via knowledge questions; sensitive data in URLs
rg -n -i 'security.?question|secret.?question|maiden'; rg -nP -i '[?&](token|password|api_?key|secret|ssn)='
# rate limiting present at all?
rg -n -i 'express-rate-limit|@nestjs/throttler|ThrottlerGuard|django_ratelimit|DEFAULT_THROTTLE|throttle_classes|flask_limiter|slowapi|AddRateLimiter|EnableRateLimiting|RateLimiter::for|throttle:|bucket4j|resilience4j|x/time/rate|httprate|limit_req'
# idempotency / webhook dedupe
rg -n -i 'idempotency[-_]?key|event\.id|constructEvent'
```
**Node (Express/NestJS/Next.js)**
- `rg -nP 'req\.body\.(price|amount|total|discount)|\.(balance|stock|credits?)\s*[-+]=' -t js -t ts` — read-modify-`save()` in Mongoose/Sequelize; prefer conditional atomic update.
- Server Actions / route handlers accepting `total` from forms; `prisma.x.update` without `where` precondition; `$transaction` absent around multi-write flows.
- NestJS: no `ThrottlerGuard` on OTP/login/coupon; DTOs exposing writable `role`/`status` (also mass assignment).

**Python (Django/FastAPI/Flask)**
- `rg -nP '\.(balance|stock|quantity|credits?)\s*[-+]=|\.save\(\)' -t py` without `F()`, `select_for_update()` inside `transaction.atomic()`.
- DRF serializers with writable `price/status/owner`; `fields = '__all__'`; pydantic request models containing `price`/`total`.
- DRF throttling docs: built-in throttles are not a brute-force/security control and can let a few extra requests through under concurrency.

**Java (Spring Boot)**
- `@RequestBody` DTOs with `price`, `total`, `role`; entities bound directly to requests.
- Read-then-write without `@Lock(LockModeType.PESSIMISTIC_WRITE)` or `@Version`; `synchronized` used as the only guard in a horizontally scaled service.
- Multi-step flows relying on `@SessionAttributes`/client hints without status checks.

**Go**
- Separate `SELECT` then `UPDATE` outside `tx`; no `FOR UPDATE`; shared maps without `sync.Mutex` (run `go test -race ./...`).
- Handlers decoding `Price`/`Total` from JSON into order structs.

**PHP (Laravel)**
- `rg -nP '\$request->(input|get)\(\s*["\x27](price|amount|total|discount|role|status)' -t php`; `Model::create($request->all())` with loose `$fillable`/`$guarded = []`.
- `$coupon->used = true; $coupon->save();` after an `if` without `DB::transaction` + `lockForUpdate()`; missing `throttle` middleware on sensitive routes.

**.NET (ASP.NET Core)**
- Model binding entities directly (over-posting); DTOs carrying price/role.
- `SaveChanges` on balance/stock without concurrency token (`[ConcurrencyCheck]`/`[Timestamp]`) or conditional `ExecuteUpdate`; `lock`/`SemaphoreSlim` as the only guard across instances.
- No `AddRateLimiter`/`[EnableRateLimiting]` on sensitive endpoints.

**False-positive notes**
- A request field named `price`/`amount` is fine if the server ignores it or it is legitimately user-chosen (donation, top-up) and bounded (min/max, currency, positive, integer minor units).
- Read-modify-write inside a serializable transaction, `SELECT … FOR UPDATE`, or with an optimistic version check is fine.
- Rate limits may live in the gateway/CDN/WAF/nginx (`limit_req`)—check infra config before flagging.
- `target="_blank"` without `rel` is implicitly `noopener` in modern browsers; `window.open()` without `noopener` still exposes `opener`.
- Clickjacking headers are often set by framework defaults or middleware—verify responses rather than code alone.

### How to detect — runtime (safe, own app only)
Local/staging only, test accounts and test data; read results from API responses and DB state.
- **Price/state tampering:** submit checkout with an altered `price`/`total`/`discount` field for a test item → server must ignore or reject it and charge the catalog price.
- **Bounds:** `quantity=-1`, `0`, very large, fractional; `amount` with extra decimals → expect 400.
- **Workflow order:** call the final step (e.g. `/checkout/confirm`) for a test order that has not completed payment → expect 409/400; repeat a completed step → no second effect.
- **Concurrency (limit overrun):** create a single-use test coupon, then send ~20 simultaneous redemptions from a test account, e.g. `seq 20 | xargs -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/api/coupons/TEST1/redeem -H "Authorization: Bearer $TEST_TOKEN"` → expect exactly one 2xx and one redemption row. Same idea for a test-wallet withdrawal (balance never negative).
- **Idempotency:** repeat a create-payment request with the same `Idempotency-Key` → one resource; same key, different body → rejected (the IETF draft suggests 422).
- **Business-flow limits:** request an OTP/SMS/reset email ~30 times for one test account → expect 429 with `Retry-After` after the documented threshold; confirm the limit key can't be reset by changing `X-Forwarded-For`.
- **Headers:** `curl -sI http://localhost:3000 | grep -iE 'content-security-policy|x-frame-options|cache-control|cross-origin-opener-policy'` (frame-ancestors, `no-store` on sensitive pages).

### Tools
- **Threat modeling:** OWASP Threat Dragon; OWASP pytm (threat model as Python code); Threagile; Microsoft Threat Modeling Tool. Use the four questions + STRIDE on DFDs with trust boundaries (OWASP Threat Modeling Cheat Sheet).
- **SAST (limited coverage for design):** Semgrep custom rules, e.g. flag `req.body.price` or `.save()` after a balance check (`semgrep scan --config p/default --config ./rules/`); CodeQL custom queries; `gosec` G113 (request smuggling); ESLint `react/jsx-no-target-blank`.
- **Concurrency:** Go race detector `go test -race ./...`; integration tests that fire parallel requests (xargs/k6); Burp Repeater "send group in parallel" for manual testing of your own staging app.
- **DAST (headers only):** ZAP baseline (passive) `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:3000`.
- **Checklists:** OWASP WSTG Business Logic Testing (WSTG-BUSL-01…10, incl. BUSL-10 Payment Functionality); ASVS 5.0 V2.

### Fix / remediation
**Server-side pricing (Node/TS)**
```ts
// BAD: total = req.body.total
// GOOD: derive everything from server data
const items = await db.product.findMany({ where: { id: { in: body.items.map(i => i.id) } } });
const total = body.items.reduce((s, i) => {
  const p = items.find(x => x.id === i.id); if (!p || !Number.isInteger(i.qty) || i.qty < 1 || i.qty > 10) throw new BadRequest();
  return s + p.priceCents * i.qty; }, 0);
```
**Atomic single-use / balance (SQL, any stack)**
```sql
-- GOOD: check and act in one statement; verify affected rows == 1
UPDATE coupons SET redeemed_by = $1, redeemed_at = now() WHERE code = $2 AND redeemed_at IS NULL;
UPDATE wallets SET balance = balance - $1 WHERE id = $2 AND balance >= $1;
-- plus: UNIQUE (coupon_id, user_id) on redemptions; CHECK (balance >= 0)
```
**Django**
```python
# BAD: acct = Account.objects.get(pk=pk); if acct.balance >= amt: acct.balance -= amt; acct.save()
# GOOD
with transaction.atomic():
    n = Account.objects.filter(pk=pk, balance__gte=amt).update(balance=F("balance") - amt)
    if n != 1: raise InsufficientFunds()
```
**Laravel / Spring**
```php
DB::transaction(function () use ($code, $user) {
    $c = Coupon::where('code', $code)->whereNull('redeemed_at')->lockForUpdate()->firstOrFail();
    $c->update(['redeemed_at' => now(), 'redeemed_by' => $user->id]);
});
```
```java
@Lock(LockModeType.PESSIMISTIC_WRITE) Optional<Wallet> findById(Long id); // or @Version for optimistic locking
```
**State machine guard:** `UPDATE orders SET status='paid' WHERE id=? AND status='pending_payment'` (rows==1) — never trust a client-sent status.
**Idempotency:** store `(user_id, idempotency_key)` with a UNIQUE constraint and the request hash + response; replay the stored response; reject mismatched bodies. Dedupe webhooks by provider event ID after signature verification.
**Rate limits:** NestJS `@nestjs/throttler`; ASP.NET Core `builder.Services.AddRateLimiter(...)` + `[EnableRateLimiting("otp")]`; Laravel `RateLimiter::for('otp', fn($r) => Limit::perMinute(3)->by($r->user()?->id ?: $r->ip()))`; Django `django-ratelimit`/DRF `ScopedRateThrottle`; Go `golang.org/x/time/rate`. Use a shared store (Redis) when running multiple instances.

### Best-practice checklist
- [ ] Threat model (four questions/STRIDE) for auth, access control, payments and other critical flows; abuse cases in user-story acceptance criteria.
- [ ] Input validation rules and cross-field consistency documented and enforced server-side (ASVS 2.1.1, 2.1.2, 2.2.1, 2.2.2, 2.2.3).
- [ ] Business limits documented per user and globally (ASVS 2.1.3) and implemented (ASVS 2.3.2).
- [ ] Flows only proceed in the expected step order, server-side (ASVS 2.3.1).
- [ ] Multi-write business operations are transactional—all or nothing (ASVS 2.3.3).
- [ ] Limited-quantity resources use locking/atomic updates, cannot be double-booked (ASVS 2.3.4); TOCTOU checks and actions are atomic (ASVS 15.4.2).
- [ ] High-value flows require multi-user approval where appropriate (ASVS 2.3.5, L3).
- [ ] Anti-automation on costly/valuable functions (ASVS 2.4.1); realistic human timing on business flows (ASVS 2.4.2, L3).
- [ ] Resource-demanding functionality identified and protected (ASVS 15.1.3, 15.2.2).
- [ ] Mass-assignment countermeasures: allowed fields per action (ASVS 15.3.3); only needed fields returned (ASVS 15.3.1).
- [ ] Client IP for rate limiting derived from trusted proxy config, not spoofable headers (ASVS 15.3.4); strict types/comparisons (ASVS 15.3.5).
- [ ] Money in integer minor units or decimal types; amounts bounded and positive.
- [ ] Idempotency keys on create/payment endpoints; webhook event dedupe.
- [ ] Uploads: extension and content both validated (ASVS 5.2.2).
- [ ] No sensitive data in URLs (ASVS 14.2.1); `Cache-Control: no-store` for sensitive responses (ASVS 14.3.2).
- [ ] Framing restricted via CSP `frame-ancestors` (ASVS 3.4.6); COOP for document responses (ASVS 3.4.8, L3).
- [ ] No knowledge-based (security-question) account recovery (NIST SP 800-63B).
- [ ] Tenant isolation enforced centrally (global query filters/row-level security), not per query.
- [ ] Unit/integration tests for negative, out-of-order and concurrent cases of every critical flow.

### Severity guidance
- **Critical:** direct financial loss or cross-tenant compromise by design—client-controlled price/total accepted; race allowing withdrawal beyond balance or unlimited credit creation; no tenant scoping on a multi-tenant API.
- **High:** single-use resources reusable via concurrency (coupon/gift card/referral); payment or verification step skippable (order marked paid, MFA/KYC skipped); security-question recovery; no limit on OTP verification attempts.
- **Medium:** no anti-automation on valuable flows (scalping, SMS pumping, signup abuse) with bounded cost; missing idempotency causing duplicate charges on retry; sensitive tokens in GET query strings; negative/zero quantities accepted but caught later.
- **Low:** defense-in-depth gaps—missing `frame-ancestors` on non-sensitive pages, `window.open` without `noopener`, undocumented limits, float money with no demonstrated abuse.
Raise one level for unauthenticated reachability or money movement; lower one level if a compensating control (gateway limits, reconciliation with manual review) demonstrably exists.

### Sources
- https://owasp.org/Top10/2025/A06_2025-Insecure_Design/
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A06_2025-Insecure_Design.md
- https://owasp.org/Top10/2025/0x00_2025-Introduction/
- https://owasp.org/Top10/2021/A04_2021-Insecure_Design/
- https://raw.githubusercontent.com/OWASP/Top10/master/2025/docs/en/A10_2025-Mishandling_of_Exceptional_Conditions.md
- https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/
- https://github.com/OWASP/ASVS/releases (5.0.0, 2025-05-30)
- https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x11-V2-Validation-and-Business-Logic.md
- https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x24-V15-Secure-Coding-and-Architecture.md
- https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x12-V3-Web-Frontend-Security.md
- https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x14-V5-File-Handling.md
- https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x23-V14-Data-Protection.md
- https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/
- https://owasp.org/www-project-top-10-for-business-logic-abuse/ (incubator project)
- https://portswigger.net/web-security/race-conditions
- https://docs.djangoproject.com/en/5.2/ref/models/expressions/
- https://www.django-rest-framework.org/api-guide/throttling/
- https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/ and https://www.ietf.org/archive/id/draft-ietf-httpapi-idempotency-key-header-07.html
- https://raw.githubusercontent.com/securego/gosec/master/RULES.md
- https://www.zaproxy.org/docs/docker/baseline-scan/
