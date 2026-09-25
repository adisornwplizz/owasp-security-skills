## A04:2025 – Cryptographic Failures
**Edition notes:** Was A02:2021 (itself renamed in 2021 from 2017's "Sensitive Data Exposure", a symptom rather than a root cause). In 2025 it moves down two places to #4. Mapped CWEs rose from 29 (2021) to 32. The official page names three weak-PRNG CWEs among the most common: CWE-327, CWE-331, CWE-1241 and CWE-338. It also adds new guidance: post-quantum readiness ("high risk systems … safe no later than the end of 2030", per ENISA), "drop support for CBC" TLS ciphers, and disabling caching of sensitive data in the CDN, web server and Redis. Its password-hash list is Argon2, yescrypt, scrypt and PBKDF2-HMAC-SHA-512, with bcrypt described only as "legacy". Hard-coded *passwords/credentials* (CWE-259/798) and certificate validation (CWE-295/297) are mapped to A07. CWE-296 (chain of trust) and CWE-321 (hard-coded crypto key) stay here. Page stats: 32 CWEs, max incidence 13.77%, avg incidence 3.80%, 1,665,348 occurrences, 2,185 CVEs.

### What it is (issue)
Sensitive data is not protected, or is protected badly, in transit or at rest. Causes include missing encryption, broken or weak algorithms and modes, weak or hard-coded keys, predictable randomness, bad IV/nonce handling, missing signature verification, and fast or unsalted password hashes. The data at risk includes passwords, tokens, PII, payment and health data, and the keys themselves. Once it is exposed or forged, the result is account takeover, token forgery, session hijack or a regulatory breach (GDPR, PCI DSS).

### Root causes
- No data classification, so nobody decided which fields need encryption, masking, no-cache or no-log.
- Developers build crypto from primitives (e.g., `createCipheriv`, `Cipher.getInstance`) instead of high-level vetted APIs (libsodium/Tink/Fernet, framework hashers).
- Legacy defaults and copy-pasted snippets: `Cipher.getInstance("AES")` (defaults to ECB in the JCE), zero IVs, MD5/SHA-1, `Rfc2898DeriveBytes` with SHA-1/low iterations.
- General-purpose PRNGs (`Math.random`, `random`, `math/rand`, `java.util.Random`) are used for security values, because they are convenient and look random.
- Keys and secrets live in code, config files, images or CI YAML because there is no secrets manager or KMS. There is no rotation, and one key serves every environment.
- Password hashing is treated as "hashing" (fast SHA-256) rather than a slow KDF, and parameters are never re-tuned as hardware improves.
- TLS verification gets disabled "temporarily" to get past self-signed certs in dev, and the change ships to prod.
- Encryption without integrity (CBC/CTR without a MAC). JWT libraries are called in "decode" mode or trust the `alg` header.
- No crypto inventory or agility, so weak algorithms can't be swapped out (ASVS 11.1.x, 11.2.2).

### Key CWEs
Official mapping (32): CWE-261, 296, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 334, 335, 336, 337, 338, 340, 342, 347, 523, 757, 759, 760, 780, 916, 1240, 1241. The ★ entries matter most for web/API developers:
- ★ CWE-327 Use of a Broken or Risky Cryptographic Algorithm (MD5/SHA-1/DES/RC4/ECB)
- ★ CWE-338 Use of Cryptographically Weak PRNG (and CWE-330/331/1241, CWE-340 predictable identifiers)
- ★ CWE-916 Use of Password Hash With Insufficient Computational Effort (CWE-759/760 unsalted or predictable salt)
- ★ CWE-321 Use of Hard-coded Cryptographic Key (JWT/session/encryption keys in source)
- ★ CWE-347 Improper Verification of Cryptographic Signature (JWT `alg:none`, decode without verify, alg confusion)
- ★ CWE-319 Cleartext Transmission of Sensitive Information (and CWE-523 Unprotected Transport of Credentials)
- ★ CWE-329 Not Using a Random IV with CBC Mode / CWE-323 Reusing a Nonce, Key Pair in Encryption
- CWE-326 Inadequate Encryption Strength (RSA < 2048, short HMAC keys), CWE-757 Algorithm Downgrade, CWE-780 RSA without OAEP, CWE-296 Improper Following of a Certificate's Chain of Trust

### How to detect — code review
**Stack-agnostic signals (where to look)**
- Auth and user modules (password hashing and reset tokens), token and session issuance, JWT middleware, "utils/crypto" helpers, and ORM models with PII columns (plaintext `ssn`, `card_number`, `dob`, `api_key`).
- Config files: `.env*`, `application*.yml|properties`, `appsettings*.json`, `settings.py`, `config/*.php`, `docker-compose*.yml`, `Dockerfile` (`ENV|ARG .*SECRET|KEY|PASSWORD`), CI (`.github/workflows`, `.gitlab-ci.yml`), IaC (`*.tf` with `password =`, and `sensitive` not set on outputs).
- TLS termination config: `nginx.conf` (`ssl_protocols`, `ssl_ciphers`, `add_header Strict-Transport-Security`), ingress annotations, load balancer TLS policies.
- Outbound HTTP/DB clients: `verify=false`/`rejectUnauthorized:false`, `sslmode=disable`, `http://` URLs to internal or external APIs.
- Generic secret regexes: `-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`, `AKIA[0-9A-Z]{16}`, `sk_live_[0-9a-zA-Z]{24,}`, `gh[pousr]_[A-Za-z0-9]{36}`, `xox[baprs]-`, `(secret|jwt_secret|api_key|private_key|app_key)\s*[:=]\s*['"][^'"]{8,}`.
- Sensitive data in URLs (`?token=`, `?api_key=`) or in `localStorage`/`sessionStorage` (ASVS 14.2.1, 14.3.3). Sensitive responses without `Cache-Control: no-store`.

**Node (Express/NestJS/Next.js)**
```
rg -n "Math\.random\(\)" -g '!*.test.*'            # near token|otp|reset|secret|nonce|salt|id
rg -n "createHash\(['\"](md5|sha1)['\"]|createHash\(['\"]sha(256|512)['\"]\)\.update\([^)]*pass"
rg -n "createCipher\(|-ecb['\"]|aes-\d+-cbc|des-|rc4|Buffer\.alloc\(16(, ?0)?\)"   # createCipher removed in Node 22
rg -n "rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|strictSSL:\s*false|minVersion:\s*['\"]TLSv1(\.1)?['\"]"
rg -n "jwt\.decode\(|algorithms:\s*\[[^\]]*none|jwt\.(sign|verify)\([^,]+,\s*['\"][^'\"]{0,31}['\"]"
rg -n "secret:\s*['\"](keyboard cat|secret|changeme)"   # express-session sample secret
```
**Python (Django/FastAPI/Flask)**
```
rg -n "hashlib\.(md5|sha1)\(|hashlib\.sha(256|512)\([^)]*pass"
rg -n "^\s*import random|random\.(choice|choices|randint|random|getrandbits)\(|uuid\.uuid1\("
rg -n "MODE_ECB|modes\.ECB\(|DES3?\.|ARC4|from Crypto\.Cipher"      # pycrypto is unmaintained
rg -n "verify\s*=\s*False|_create_unverified_context|CERT_NONE|check_hostname\s*=\s*False"
rg -n "options=\{[^}]*verify_signature['\"]:\s*False|SECRET_KEY\s*=\s*['\"]|secret_key\s*=\s*['\"]"
rg -n "MD5PasswordHasher|UnsaltedSHA1|SECURE_HSTS_SECONDS\s*=\s*0|SESSION_COOKIE_SECURE\s*=\s*False"
```
**Java (Spring Boot)**
```
rg -n "MessageDigest\.getInstance\(\"(MD5|SHA-?1)\"|DigestUtils\.(md5|sha1)"
rg -n "Cipher\.getInstance\(\"(AES|DES[a-z]*|RC4|Blowfish)\"\)|/ECB/|RSA/ECB/PKCS1Padding|new IvParameterSpec\(new byte"
rg -n "new Random\(|Math\.random\(|RandomStringUtils\.random"   # use SecureRandom / RandomStringUtils.secure()
rg -n "NoOpPasswordEncoder|StandardPasswordEncoder|MessageDigestPasswordEncoder|Md4PasswordEncoder|LdapShaPasswordEncoder"
rg -n "X509TrustManager|checkServerTrusted\([^)]*\)\s*\{\s*\}|NoopHostnameVerifier|\(hostname, session\) -> true"
rg -n "SSLContext\.getInstance\(\"(SSL|TLSv1(\.1)?)\"\)|enabled-protocols.*TLSv1(\.1)?\b"
```
**Go**
```
rg -n "\"crypto/(md5|sha1|des|rc4)\"|\"math/rand(/v2)?\""   # math/rand near token generation
rg -n "InsecureSkipVerify:\s*true|MinVersion:\s*tls\.VersionTLS1[01]"
rg -n "sha256\.Sum256\(\[\]byte\(pass|rsa\.GenerateKey\([^,]+,\s*(512|1024)\)|NewCBCEncrypter|iv\s*:?=\s*\[\]byte\(\""
rg -n "jwt\.ParseUnverified|SigningMethodNone|UnsafeAllowNoneSignatureType"
```
**PHP (Laravel)**
```
rg -n "\b(md5|sha1)\(\s*\\\$pass|hash\(['\"]sha(256|512)['\"],\s*\\\$pass|crypt\("
rg -n "\b(rand|mt_rand|uniqid|lcg_value)\("                  # use random_bytes/random_int/Str::random
rg -n "openssl_encrypt\([^)]*(ecb|des|rc4)|CURLOPT_SSL_VERIFY(PEER|HOST)\s*=>\s*(false|0)|'verify'\s*=>\s*false|withoutVerifying\(\)"
rg -n "^APP_KEY=base64:" .env* ; git ls-files | rg "(^|/)\.env$"   # committed .env / APP_KEY
```
**.NET (ASP.NET Core)**
```
rg -n "MD5\.Create|SHA1\.Create|MD5CryptoServiceProvider|DESCryptoServiceProvider|TripleDES|RC2"
rg -n "CipherMode\.ECB|new Random\(|Random\.Shared"         # RandomNumberGenerator instead
rg -n "new Rfc2898DeriveBytes\(|ServerCertificateCustomValidationCallback\s*=.*=>\s*true|DangerousAcceptAnyServerCertificateValidator"
rg -n "SslProtocols\.(Tls|Tls11|Ssl3)\b|SecurityProtocolType\.(Tls|Tls11|Ssl3)\b|IterationCount\s*=\s*\d{1,5}\b"
rg -n "\"(Key|Secret|SigningKey|ConnectionString)\"\s*:\s*\"[^\"]{8,}" appsettings*.json
```
**Parameter spot-checks (hash prefixes in DB/fixtures).** OWASP Password Storage CS minimums: Argon2id m=19456 KiB (19 MiB), t=2, p=1, or the equivalents (46 MiB/t1, 12 MiB/t3, 9 MiB/t4, 7 MiB/t5). scrypt N=2^17, r=8, p=1 (or 2^16/p2, 2^15/p3, 2^14/p5, 2^13/p10). bcrypt cost ≥10 with a 72-byte input limit (legacy only). PBKDF2-HMAC-SHA256 600,000, SHA512 220,000, SHA1 1,400,000 (legacy only).
- Framework defaults vs those minimums (verified from source):
  - Django 6.1: PBKDF2-SHA256 1,500,000 iterations (OK). Argon2 is t=2, m=102400, p=8 (OK).
  - Spring `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`: m=16384 KiB, t=2, p=1. **Below 19 MiB/t=2.**
  - Spring `Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()`: 310,000 × SHA-256. **Below 600k.** The `DelegatingPasswordEncoder` default is bcrypt(10), which is acceptable as legacy.
  - ASP.NET Core Identity v3: PBKDF2-HMAC-SHA512 × 100,000. **Below 220k.** Raise `PasswordHasherOptions.IterationCount`.
  - Laravel 13: bcrypt rounds 12, or argon m=65536, t=4, p=1 (OK).
  - PHP 8.4 `password_hash` default bcrypt cost is 12 (it was 10).
  - node-argon2: argon2id m=65536, t=3, p=4 (OK). argon2-cffi: m=65536, t=3, p=4 (OK).
  - Node `crypto.scrypt` default N=16384, r=8, p=1. **Below the minimum.** Raise N or p, and raise `maxmem`, whose 32 MiB default is too small for N=2^17.
- Signs of weak hashes in data: 32 hex chars = MD5, 40 = SHA-1, 64 = plain SHA-256. Good formats look like `$argon2id$v=19$m=…`, `$2b$12$…`, `pbkdf2_sha256$1500000$…`.

**False-positive notes**
- MD5/SHA-1 used for non-security purposes (ETags, cache keys, dedup, Git object IDs, HIBP k-anonymity lookups, which require SHA-1 prefixes) is fine. Python `hashlib.md5(..., usedforsecurity=False)` marks this explicitly.
- A fast SHA-256 over *high-entropy* tokens (API keys, reset tokens ≥128 bits) is acceptable; ASVS 6.5.2 only requires a slow hash below 112 bits of entropy. Flag it only when the input is a human password.
- `Math.random`/`random` used for UI, jitter, backoff, sampling or tests is fine. `nanoid`, Laravel `Str::random`, `secrets.*`, `crypto.randomUUID()` and `crypto/rand` are CSPRNG-backed. However, ASVS 11.5.1 says UUIDs do not meet the 128-bit requirement for secrets.
- Dummy or test keys in fixtures, `*.example` env files, and docs are fine. Confirm the file is not loaded in prod and the value doesn't match a real key (use TruffleHog/Gitleaks verification).
- `verify=False`/`InsecureSkipVerify` in tests against local mocks is fine. Flag it only if reachable from production code paths or controlled by an env flag defaulting to insecure.
- AES-CBC with a random IV *and* an HMAC (encrypt-then-MAC, e.g., Laravel's Encrypter or Fernet) is authenticated. It isn't ideal, but it isn't a finding under ASVS 11.3.3.

### How to detect — runtime (safe, own app only)
- HTTPS enforcement: `curl -sI http://localhost:8080/login` should return a 301/308 to `https://`. `curl -skI https://staging.local/ | grep -i strict-transport` should show `max-age` ≥ 31536000 (ASVS 3.4.1). Mozilla's guideline uses 63072000.
- TLS configuration (staging or your own host): `testssl.sh --quiet --severity MEDIUM https://staging.example.com`, `sslyze staging.example.com:443 --mozilla_config=intermediate` (a non-zero exit means non-compliant), and `openssl s_client -connect staging.example.com:443 -tls1_1 </dev/null`, which should fail the handshake.
- Cookies: log in with a test user and inspect `Set-Cookie`. Session cookies need `Secure; HttpOnly; SameSite`, ideally with a `__Host-` prefix.
- Caching: authenticated JSON or pages that return PII should carry `Cache-Control: no-store` (ASVS 14.3.2). Use `curl -sk -D- -o /dev/null -H "Authorization: Bearer $T" https://localhost/api/me`.
- Token randomness: request 3–5 password-reset or verification tokens for *your own* test account (read them from Mailpit/MailHog). They should be long (≥22 base64url chars ≈128 bits), with no sequential or time-based pattern and no shared prefixes.
- JWT inspection: `echo "$T" | cut -d. -f1 | base64 -d 2>/dev/null` should show the expected `alg` (e.g., RS256/ES256/EdDSA) and a `kid`. Flip one character of the signature and replay the token to your local API: expect 401. Send a token signed with a different local key: expect 401.
- Password storage (local dev DB only): `SELECT password FROM users LIMIT 3;` and compare the prefixes and parameters to the minimums above.
- Leaked material: `curl -s -o /dev/null -w '%{http_code}' https://localhost/.env` (and `/.git/HEAD`) should return 404.

### Tools
- **Semgrep:** `semgrep scan --config p/secrets --config p/jwt --config p/insecure-transport --config p/owasp-top-ten`. Useful rules (full ID = file path + rule id):
  - `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret`
  - `javascript.jsonwebtoken.security.jwt-none-alg.jwt-none-alg`
  - `python.jwt.security.unverified-jwt-decode.unverified-jwt-decode`
  - `java.lang.security.audit.crypto.ecb-cipher.ecb-cipher`
  - `java.lang.security.audit.crypto.no-static-initialization-vector.no-static-initialization-vector`
  - `go.lang.security.audit.crypto.math_random.math-random-used`
  - `python.cryptography.security.insecure-cipher-mode-ecb.insecure-cipher-mode-ecb`
  - `php.lang.security.openssl-cbc-static-iv.openssl-cbc-static-iv`
  - The registry rulesets themselves could not be fetched from this sandbox. Ruleset names were confirmed from secondary sources, and rule IDs from the semgrep-rules repository.
- **Gitleaks** (v8.19+ syntax): `gitleaks git -v --report-format sarif --report-path gitleaks.sarif .` for history, and `gitleaks dir .` for the working tree. Add it as a pre-commit hook.
- **TruffleHog:** `trufflehog git file://. --results=verified,unknown` and `trufflehog filesystem .`. Verification calls the providers' APIs; use `--no-verification` for offline scans.
- **Bandit (Python):** `bandit -r . -t B105,B106,B107,B303,B304,B305,B311,B323,B324,B413,B501,B502,B503,B504,B505`.
- **gosec (Go):** `gosec -include=G101,G401,G402,G403,G404,G405,G406,G407,G501,G502,G503,G505 ./...`. G407 flags a hard-coded IV/nonce.
- **Java:** SpotBugs + Find Security Bugs. Relevant patterns: `WEAK_MESSAGE_DIGEST_MD5/SHA1`, `PREDICTABLE_RANDOM`, `ECB_MODE`, `STATIC_IV`, `CIPHER_INTEGRITY`, `WEAK_TRUST_MANAGER`, `WEAK_HOSTNAME_VERIFIER`, `HARD_CODE_KEY`.
- **.NET analyzers:** CA5350/CA5351 (weak or broken algorithms), CA5358 (unsafe cipher modes), CA5359 (disabled certificate validation), CA5379/CA5387/CA5388 (weak KDF or iterations), CA5390 (hard-coded key), CA5394 (insecure randomness), CA5397 (deprecated SslProtocols), CA5401/CA5402 (IV).
- **Node:** `eslint-plugin-security` (`security/detect-pseudoRandomBytes`), `njsscan .`.
- **TLS/DAST:** `testssl.sh`, `sslyze` (checks against Mozilla intermediate by default), `nmap --script ssl-enum-ciphers -p 443 host`. For a passive ZAP scan, run `docker run -t ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t https://staging.example.com`. Its relevant alerts are 10035 (HSTS missing), 10011 (cookie without Secure), 10040 (mixed content), 10106 (HTTP-only site), 10024 (sensitive data in URL) and 10097 (hash disclosure).

### Fix / remediation
- **Password hashing:** Argon2id at OWASP parameters. Store it in PHC format and rehash on login when the parameters change (`needsRehash`/`check_needs_rehash`, Laravel `rehash_on_login`). Upgrade legacy MD5/SHA hashes by wrapping them (`argon2id(md5_hash)`), then replace with a direct hash at the next login.
```js
// Node BAD
const h = crypto.createHash('sha256').update(pw).digest('hex');
// Node GOOD (node-argon2 defaults: argon2id m=64MiB t=3 p=4 ≥ OWASP min; Node ≥24.7 also has crypto.argon2)
import argon2 from 'argon2';
const h = await argon2.hash(pw);  const ok = await argon2.verify(h, pw);
```
```python
# Python BAD
hashlib.md5(pw.encode()).hexdigest()
# Python GOOD (argon2-cffi defaults = RFC 9106 low-memory: id, t=3, m=65536, p=4)
from argon2 import PasswordHasher
ph = PasswordHasher(); h = ph.hash(pw); ph.verify(h, pw); ph.check_needs_rehash(h)
# Django: PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher", ...]  (pip install django[argon2])
```
```java
// Spring BAD: new MessageDigestPasswordEncoder("MD5") / NoOpPasswordEncoder.getInstance()
// Spring GOOD: explicit params ≥ OWASP (defaultsForSpringSecurity_v5_8 uses only 16 MiB)
PasswordEncoder enc = new Argon2PasswordEncoder(16, 32, 1, 19456, 2);  // salt, hash, p, m(KiB), t
```
- **Randomness:** use only CSPRNGs for tokens, IDs used as secrets, OTPs, salts, IVs and keys, with ≥128 bits (ASVS 11.5.1).
```js
Math.random().toString(36).slice(2)          // BAD
crypto.randomBytes(32).toString('base64url') // GOOD
```
```python
''.join(random.choices(string.ascii_letters, k=20))  # BAD
secrets.token_urlsafe(32)                              # GOOD
```
  - Go: `crypto/rand.Read(b)` or `rand.Text()` (Go 1.24+).
  - Java: `SecureRandom`.
  - .NET: `RandomNumberGenerator.GetBytes(32)`.
  - PHP: `bin2hex(random_bytes(32))`.
- **Symmetric encryption:** use AEAD (AES-256-GCM or ChaCha20-Poly1305) with a unique 96-bit nonce per (key, message), and never reuse a nonce under the same key. Better still, use a high-level library (libsodium `crypto_secretbox`, Google Tink, Python `cryptography` Fernet/AESGCM).
```java
Cipher.getInstance("AES");                        // BAD → AES/ECB/PKCS5Padding
Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); // GOOD
byte[] iv = new byte[12]; new SecureRandom().nextBytes(iv);
c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));  // store iv with ciphertext
```
- **Keys and secrets:** load them from a secrets manager or KMS (Vault, AWS/GCP/Azure KMS, Key Vault) at runtime. Use envelope encryption (DEK wrapped by a KEK), separate keys per environment, and rotation. After a secret is committed: **rotate it first**, then purge it from history (`git filter-repo`). Removing it from history alone is not enough.
- **JWT signing:** prefer asymmetric signing (ES256/EdDSA/RS256 with ≥2048-bit RSA; ASVS 11.2.3 wants 3072-bit RSA for 128-bit security). If you use HS256, the secret must be ≥256 bits of CSPRNG output (RFC 7518 §3.2; OWASP JWT CS) and never a password-like string. Pin the algorithm on verification (details in A07). PyJWT ≥2.11 warns on short HMAC keys; set `enforce_minimum_key_length=True` to make that an error.
- **TLS:** use TLS 1.2 and 1.3 only, with AEAD and forward-secret suites only (Mozilla Server Side TLS v6.0 "intermediate"; "modern" means TLS 1.3 only). Send HSTS with `max-age` ≥1 year and `includeSubDomains`, and redirect HTTP to HTTPS. Watch the framework defaults:
  - ASP.NET Core `UseHsts()` defaults to 30 days, so set `MaxAge`.
  - Django needs `SECURE_HSTS_SECONDS`, `SECURE_SSL_REDIRECT`, `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` set explicitly.
  - Laravel needs `SESSION_SECURE_COOKIE=true`.
  - Keep certificate validation on in all clients, and use a private CA bundle instead of disabling verification.
```go
tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10} // BAD
tls.Config{MinVersion: tls.VersionTLS12, RootCAs: internalPool}   // GOOD
```
- **Sensitive data:** collect and keep less of it. Tokenize or truncate PANs, encrypt PII columns at the application level (or with DB TDE plus column encryption for high-value fields), and send `Cache-Control: no-store` on sensitive responses. Keep secrets out of URLs, logs and `localStorage`.

### Best-practice checklist
- [ ] Sensitive data is inventoried and classified, with protection rules per class (ASVS 14.1.1, 14.1.2). A crypto inventory exists (11.1.2).
- [ ] Passwords use Argon2id (≥19 MiB, t=2, p=1), scrypt (N=2^17, r=8, p=1), bcrypt cost ≥10 (legacy), or PBKDF2-SHA256 ≥600k (FIPS). Rehash on login (11.4.2).
- [ ] No MD5/SHA-1 for any security purpose (11.4.1). Signature and integrity hashes are ≥256-bit (11.4.3).
- [ ] No ECB and no PKCS#1 v1.5 encryption (11.3.1). Only approved AEAD such as AES-GCM (11.3.2, 11.3.3). Nonces and IVs are never reused per key (11.3.4).
- [ ] All primitives give ≥128-bit security, e.g., RSA ≥3072 or ECC P-256/X25519 (11.2.3). Industry-validated libraries are used (11.2.1).
- [ ] Every security-relevant random value comes from a CSPRNG and carries ≥128 bits of entropy. No UUIDs as secrets (11.5.1).
- [ ] No keys or secrets in source, images or CI logs. A secrets manager or vault is used (13.3.1), with least-privilege access (13.3.2). Gitleaks runs in pre-commit and CI.
- [ ] JWTs and other self-contained tokens: signature verified (9.1.1), `alg` allowlisted with `none` excluded (9.1.2), keys only from trusted, pre-configured sources, with `jku`/`x5u`/`jwk` allowlisted (9.1.3).
- [ ] TLS 1.2+ only with the 1.3 preference (12.1.1) and strong suites (12.1.2). TLS on all external traffic (12.2.1) and internal traffic (12.3.1, 12.3.3). Clients validate certificates (12.3.2).
- [ ] HSTS with max-age ≥1 year, plus `includeSubDomains` at L2 (3.4.1). Cookies are `Secure` and use `__Host-`/`__Secure-` prefixes (3.3.1).
- [ ] No sensitive data in URLs (14.2.1). `Cache-Control: no-store` on sensitive responses (14.3.2). No sensitive data in browser storage apart from session tokens (14.3.3).
- [ ] A post-quantum migration plan is documented for high-risk data (11.1.4, L3). Track hybrid ML-KEM TLS groups, e.g., X25519MLKEM768 in Mozilla v6.0.

### Severity guidance
- **Critical:** a live production secret committed or baked into an image (cloud keys, DB passwords, a JWT/HMAC signing key, or the `APP_KEY`/`SECRET_KEY` that signs sessions); JWT signatures not verified, or `alg:none` or algorithm confusion accepted (forgery leads to auth bypass); passwords or PANs stored in plaintext or reversibly encrypted; credentials sent over plain HTTP in production.
- **High:** passwords stored as MD5, SHA-1 or unsalted or fast SHA-2; reset, session or API tokens from a non-CSPRNG or with low entropy; ECB or a static IV/nonce on sensitive data, or GCM nonce reuse; outbound TLS verification disabled on a production path carrying credentials or PII; HS256 with a short, guessable secret.
- **Medium:** TLS 1.0/1.1 or CBC/non-FS suites enabled; HSTS missing or shorter than a year; a password KDF below OWASP parameters (e.g., the ASP.NET Identity 100k×SHA-512 or Spring PBKDF2 310k defaults, or bcrypt cost <10); sensitive responses cacheable, or secrets in URLs or logs; RSA-2048 where the policy requires 128-bit security; AES-CBC without a MAC.
- **Low / Info:** weak hashes used for non-security purposes (verify first); Argon2 settings slightly under the minimum; no crypto inventory, key-rotation schedule or PQC plan; dev-only `verify=False` guarded by an environment flag.

### Sources
- https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/ (served from top10.owasp.org)
- https://owasp.org/Top10/2021/A02_2021-Cryptographic_Failures/
- https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html (and GitHub source OWASP/CheatSheetSeries)
- https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html
- https://github.com/OWASP/ASVS/tree/v5.0.0/5.0/en (V3, V9, V11, V12, V13, V14)
- https://ssl-config.mozilla.org/guidelines/latest.json (Mozilla Server Side TLS v6.0)
- https://datatracker.ietf.org/doc/draft-ietf-oauth-rfc8725bis/ (JWT BCP update, in RFC Editor queue Aug 2026)
- https://pages.nist.gov/800-63-4/sp800-63b.html (password hashing: salt ≥32 bits, approved KDF)
- https://docs.djangoproject.com/en/6.1/releases/6.1/ ; https://github.com/django/django (hashers.py, global_settings.py)
- https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html ; spring-security Argon2PasswordEncoder/Pbkdf2PasswordEncoder source
- https://github.com/dotnet/aspnetcore (PasswordHasherOptions.cs) ; https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-configuration
- https://github.com/laravel/framework/blob/13.x/config/hashing.php ; https://php.watch/versions/8.4/password_hash-bcrypt-cost-increase
- https://github.com/ranisalt/node-argon2 ; https://github.com/hynek/argon2-cffi ; https://nodejs.org/en/blog/release/v24.7.0
- https://pkg.go.dev/golang.org/x/crypto/bcrypt ; https://pkg.go.dev/golang.org/x/crypto/argon2
- https://pyjwt.readthedocs.io/en/stable/changelog.html
- https://github.com/gitleaks/gitleaks ; https://github.com/trufflesecurity/trufflehog ; https://github.com/nabla-c0d3/sslyze
- https://github.com/PyCQA/bandit (blacklists/calls.py) ; https://github.com/securego/gosec/blob/master/RULES.md ; https://github.com/semgrep/semgrep-rules
- https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/security-warnings
- https://www.zaproxy.org/docs/alerts/
