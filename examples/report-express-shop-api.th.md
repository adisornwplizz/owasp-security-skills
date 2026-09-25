> **ตัวอย่างผลลัพธ์ (ไม่ได้แก้ไข)** สร้างโดย `owasp-top10-review` v1.0.0 เมื่อ 2026-09-25 จาก fixture ที่ตั้งใจให้มีช่องโหว่ [`evals/fixtures/shop-api`](../evals/fixtures/shop-api) (Express) · Prompt: *"ช่วยตรวจ security ของโปรเจกต์ shop-api นี้ตาม OWASP Top 10 ให้หน่อยครับ อาทิตย์หน้าจะ deploy ขึ้น production แล้ว"*

# OWASP Security Review — shop-api

> Standard: OWASP Top 10:2025 + OWASP API Security Top 10:2023 (ไม่มีการเรียก LLM จึงไม่ใช้ LLM Top 10)
> Date: 2026-09-25 · Scope: full repo · Commit: 618a611 (master; ไม่มีการแก้ไขที่ยังไม่ commit นอกจากโฟลเดอร์ `.security-review/` ที่รีวิวนี้สร้าง)
> Reviewer: Claude (owasp-top10-review skill) — automated + manual code review (ไม่มี runtime check เพราะไม่มีแอปที่รันอยู่)

## 1. Executive summary

**Overall risk: Critical** — ใครก็ได้ (บางจุดไม่ต้อง login) ปลอมตัวเป็น user อื่น, ดึงข้อมูลลูกค้าทั้งระบบ, รัน SQL บนฐานข้อมูล และตั้งราคาสินค้าเองได้ **→ ยังไม่ควร deploy ขึ้น production (No-go)** จนกว่าจะแก้ Critical และ High ทั้งหมด

| Critical | High | Medium | Low | Info |
|---|---|---|---|---|
| 9 | 7 | 9 | 2 | 1 |

**Fix first:**
1. เขียน `requireAuth` ใหม่ให้ใช้ `jwt.verify` (pin algorithm) และตอบ 401 เมื่อไม่มี/ token ไม่ถูกต้อง, ลบ secret fallback และเอา `.env` ออกจาก git แล้ว rotate credential (F-001, F-002, F-010)
2. เปลี่ยน SQL ที่ต่อ string ให้ใช้ parameter และลบ `/api/v1/export/orders` ที่เปิดสาธารณะ (F-003, F-005)
3. ใส่การตรวจสิทธิ์ฝั่ง server: ผูก `orders/:id` กับเจ้าของ, `requireRole('admin')` ให้ admin/tools route, allowlist field ใน `PUT /me`, คำนวณราคาจาก DB และจำกัด URL ของ preview (F-004, F-006 – F-009)

## 2. Coverage matrix

Status legend: ❌ issues found · ⚠️ needs manual verification / partially reviewed · ✅ no issues found in reviewed scope · N/A not applicable

| Category | Status | Findings | Notes |
|---|---|---|---|
| A01:2025 Broken Access Control | ❌ | F-004, F-005, F-006, F-007, F-012 | IDOR, route ไม่มี auth, admin ไม่เช็ค role, SSRF, response รั่ว field ภายใน. CSRF: N/A (ใช้ Bearer token ไม่ใช่ cookie) |
| A02:2025 Security Misconfiguration | ❌ | F-017, F-020, F-022 | CORS สะท้อนทุก origin, ไม่มี security headers, Dockerfile รันเป็น root และ copy `.env` เข้า image |
| A03:2025 Software Supply Chain Failures | ❌ | F-015, F-028 | express/qs/jsonwebtoken/lodash/node-fetch เก่า, Node 14 EOL, ไม่มี CI scanning |
| A04:2025 Cryptographic Failures | ❌ | F-001, F-011 | JWT ไม่ verify signature, password เป็น MD5 ไม่มี salt |
| A05:2025 Injection | ❌ | F-003, F-013 | SQLi 2 จุด, DOM XSS ใน `public/index.html`. ไม่พบ command/template injection |
| A06:2025 Insecure Design | ❌ | F-009, F-021 | ราคามาจาก client, ไม่มี cap ของ `limit`/timeout |
| A07:2025 Authentication Failures | ❌ | F-010, F-019, F-024, F-026, F-027 | secret fallback hard-code + `.env` ใน git, ไม่มี rate limit, token 30 วัน, user enumeration |
| A08:2025 Software or Data Integrity Failures | ❌ | F-008, F-023 | mass assignment `role`, CDN script ไม่มี SRI. ไม่พบ deserialization/webhook |
| A09:2025 Security Logging & Alerting Failures | ❌ | F-014, F-025 | log password แบบ plaintext, ไม่ log security event; alerting อยู่นอก repo (⚠️ ต้องถามทีม ops) |
| A10:2025 Mishandling of Exceptional Conditions | ❌ | F-002, F-016, F-018 | auth middleware fail-open, async error ไม่ถูกจับ, ส่ง stack trace ให้ client |
| API1:2023 BOLA | ❌ | F-004 | `GET /api/orders/:id` |
| API2:2023 Broken Authentication | ❌ | F-001, F-002, F-010, F-011, F-019, F-024 | |
| API3:2023 BOPLA | ❌ | F-008, F-012 | เขียน `role` ได้ / อ่าน `password_hash`, `reset_token` ได้ |
| API4:2023 Unrestricted Resource Consumption | ❌ | F-021 | `limit` ไม่มีเพดาน, outbound fetch ไม่มี timeout/size |
| API5:2023 BFLA | ❌ | F-005, F-006, F-007 | admin/tools route ไม่มี role check |
| API6:2023 Sensitive Business Flows | ❌ | F-009, F-019 | checkout ตั้งราคาเองได้, register/login ไม่มี anti-automation |
| API7:2023 SSRF | ❌ | F-007 | `POST /api/tools/preview` |
| API8:2023 Security Misconfiguration | ❌ | F-017, F-018, F-020 | |
| API9:2023 Improper Inventory Management | ❌ | F-005 | `/api/v1` (deprecated 2024) ยัง mount อยู่; ไม่มี OpenAPI spec |
| API10:2023 Unsafe Consumption of APIs | ❌ | F-007, F-021 | ใช้ HTML จาก URL ภายนอกโดยไม่มี timeout/redirect/size limit |

"✅" means nothing was found in what was reviewed. It is not a guarantee: no review or tool fully covers the Top 10.

## 3. Findings

> ทุกข้อด้านล่างมาจากการอ่านโค้ด (ไม่มี runtime test) — ระดับความมั่นใจระบุในแต่ละข้อ. ลำดับ: Critical → High → ตาราง Medium/Low/Info.
> หลายข้อ "ต่อกันได้" (chain) — เช่น F-001 ทำให้ใครก็ปลอมตัวเป็น user ใดก็ได้ ซึ่งขยายผลของ F-012 และทำให้ทุก route ที่ต้อง login เปิดให้คนนอก ทุกข้อจึงต้องแก้ ไม่ใช่แค่ข้อแรก

### F-001 · Auth middleware ไม่ตรวจลายเซ็น JWT (ใครก็ปลอม token เป็น user ใดก็ได้) — Critical
- **Category:** A04:2025 Cryptographic Failures · API2:2023 Broken Authentication · CWE-347 (tag: A07)
- **Location:** `src/middleware/auth.js:8` · **Confidence:** Confirmed · **L×I:** H×H — ไม่ต้องรู้ secret, ทำได้ทันที; ได้สิทธิ์ของ user ทุกคน
- **Evidence:**
  ```js
  const token = header.replace('Bearer ', '');
  try {
    const payload = jwt.decode(token);          // decode only, no signature check
    req.user = { id: payload.sub, role: payload.role };
    next();
  ```
- **Impact:** `jwt.decode()` แค่ถอด base64 ผู้โจมตีสร้าง token เองโดยใส่ `sub` เป็น id ของใครก็ได้ (และ `role` อะไรก็ได้) → อ่านโปรไฟล์ + `reset_token` ของคนอื่น (F-012), แก้อีเมลของคนอื่น, ดูออเดอร์และสั่งซื้อในชื่อคนอื่น — คือ account takeover ทุกบัญชี
- **Fix:** (แก้พร้อม F-002 ในฟังก์ชันเดียว; ต้อง upgrade `jsonwebtoken` เป็น ^9 ก่อน — F-015)
  ```js
  const { JWT_SECRET } = require('../config');
  function requireAuth(req, res, next) {
    const [scheme, token] = (req.headers.authorization || '').split(' ');
    if (scheme !== 'Bearer' || !token) return res.status(401).json({ error: 'unauthorized' });
    try {
      const p = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'], issuer: 'shop-api', audience: 'shop-web' });
      req.user = { id: p.sub, role: p.role };
      return next();
    } catch { return res.status(401).json({ error: 'unauthorized' }); }
  }
  // routes/auth.js:16 → jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET,
  //   { algorithm: 'HS256', expiresIn: '1h', issuer: 'shop-api', audience: 'shop-web' })
  ```
- **Verify:** test: token ที่เซ็นด้วย key อื่น หรือไม่มีลายเซ็น → `GET /api/users/me` ได้ 401

### F-002 · Auth middleware "fail-open": ไม่มี token ก็ผ่าน → admin list และ SSRF ใช้ได้โดยไม่ login — Critical
- **Category:** A10:2025 Mishandling of Exceptional Conditions · API2:2023 · CWE-636, CWE-306 (tag: A07)
- **Location:** `src/middleware/auth.js:11-13` (ส่งผลต่อ `src/routes/users.js:22`, `src/routes/tools.js:6`) · **Confidence:** Confirmed · **L×I:** H×H — ไม่ต้อง login; ได้ PII ทั้งระบบ + SSRF
- **Evidence:**
  ```js
  } catch (e) {
    // token malformed - let the request continue so public pages still work
    next();
  }
  ```
- **Impact:** request ที่ไม่มี header `Authorization` → `jwt.decode('')` คืน `null` → `payload.sub` throw → `catch` เรียก `next()` โดย `req.user` ว่าง. Handler ที่ไม่อ่าน `req.user` จึงทำงานให้คนนอก: `GET /api/users/admin/all` (อีเมล + role ของ user ทุกคน) และ `POST /api/tools/preview` (F-007). Route อื่นพังด้วย `TypeError` แทน (F-016)
- **Fix:** ใน `catch` ต้อง `return res.status(401)...` ตามโค้ดใน F-001 (หน้า public ไม่ได้ผ่าน middleware นี้อยู่แล้ว เพราะ `express.static` mount ก่อน)
- **Verify:** request ที่ไม่มี `Authorization` ไป `/api/users/admin/all` และ `/api/tools/preview` → 401 และ handler ไม่ถูกเรียก

### F-003 · SQL injection ใน login (route สาธารณะ) และใน `limit` ของรายการออเดอร์ — Critical
- **Category:** A05:2025 Injection · CWE-89
- **Location:** `src/routes/auth.js:11` (+1 similar: `src/routes/orders.js:8`) · **Confidence:** Confirmed · **L×I:** H×H — route สาธารณะ; อ่าน/แก้ฐานข้อมูลทั้งหมด
- **Evidence:**
  ```js
  // auth.js:11 — POST /api/auth/login (public)
  const result = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
  // orders.js:7-8
  const limit = req.query.limit || 20;
  const r = await db.query('SELECT * FROM orders WHERE user_id = $1 LIMIT ' + limit, [req.user.id]);
  ```
- **Impact:** ค่า `email` ที่มี quote หรือ SQL syntax ถูกตีความเป็น SQL. Query นี้ไม่มี parameter ทำให้ `pg` ใช้ simple-query protocol ซึ่งรันได้หลาย statement → ผู้โจมตีที่ไม่ได้ login อ่าน/แก้ได้ทุกตาราง (password hash, reset token, orders) และบังคับให้ query คืน row ที่ตัวเองกำหนดเพื่อ login เป็นใครก็ได้. `limit` ที่ไม่ใช่ตัวเลขถูกต่อท้าย SQL เช่นกัน (register เปิดให้ทุกคน จึงเข้าถึงได้ง่าย)
- **Fix:**
  ```js
  // auth.js
  if (typeof email !== 'string' || typeof password !== 'string') return res.status(400).end();
  const result = await db.query('SELECT id, role, password_hash FROM users WHERE email = $1', [email]);
  // orders.js
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  const r = await db.query(
    'SELECT id, product_id, quantity, total FROM orders WHERE user_id = $1 ORDER BY id DESC LIMIT $2',
    [req.user.id, limit]);
  ```
- **Verify:** unit test: `db.query` ถูกเรียกด้วย SQL ที่มี `$1` และ email อยู่ใน params array; `?limit=abc` → query ใช้ `LIMIT $2` ด้วยค่า 20

### F-004 · IDOR: ดูออเดอร์ของลูกค้าคนอื่นได้ด้วยการเปลี่ยน id — Critical
- **Category:** A01:2025 Broken Access Control · API1:2023 BOLA · CWE-639
- **Location:** `src/routes/orders.js:14` · **Confidence:** Confirmed · **L×I:** H×H — user ใดก็ได้ (register เองได้); ข้อมูลของลูกค้าทุกคน
- **Evidence:**
  ```js
  router.get('/:id', async (req, res) => {
    const r = await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
    if (!r.rows[0]) return res.status(404).end();
    res.json(r.rows[0]);
  ```
- **Impact:** query ไม่ผูกกับ `req.user.id` → ไล่ id เพื่ออ่านออเดอร์ของทุกคน (สินค้า จำนวน ยอดเงิน และ column อื่นใน `orders`)
- **Fix:**
  ```js
  const r = await db.query(
    'SELECT id, product_id, quantity, total FROM orders WHERE id = $1 AND user_id = $2',
    [req.params.id, req.user.id]);
  if (!r.rows[0]) return res.status(404).end();   // 404 (not 403) so other users' ids can't be confirmed
  ```
- **Verify:** integration test สอง user: token ของ B → `GET /api/orders/<id ของ A>` ได้ 404

### F-005 · `/api/v1/export/orders` (legacy) ไม่มี auth เลย — ดาวน์โหลดออเดอร์ทั้งระบบได้ — Critical
- **Category:** A01:2025 Broken Access Control · API9:2023 Improper Inventory Management · API5:2023 · CWE-862, CWE-306
- **Location:** `src/server.js:12`, `src/routes/legacy.js:6-8` · **Confidence:** Confirmed · **L×I:** H×H — ไม่ต้อง login; ออเดอร์ของลูกค้าทุกคน
- **Evidence:**
  ```js
  app.use('/api/v1', require('./routes/legacy'));        // server.js:12 — no requireAuth
  // v1 export used by the old mobile app (deprecated 2024, kept for now)
  router.get('/export/orders', async (req, res) => {
    const r = await db.query('SELECT * FROM orders');    // all rows, all columns, no pagination
    res.json(r.rows);
  ```
- **Impact:** ใครก็ได้บนอินเทอร์เน็ตดึงออเดอร์ทั้งหมดของทุกลูกค้าได้ในคำขอเดียว และการดึงซ้ำ ๆ ยังเป็นภาระหนักต่อ DB
- **Fix:** ลบ route นี้ (deprecated ตั้งแต่ 2024) — ลบ `server.js:12` และ `src/routes/legacy.js`. ถ้าแอปมือถือเก่ายังต้องใช้จริง ให้ mount ใต้ auth + role และระบุ column + pagination:
  ```js
  app.use('/api/v1', requireAuth, requireRole('admin'), require('./routes/legacy'));
  ```
- **Verify:** `GET /api/v1/export/orders` ที่ไม่มี token → 404 (ถ้าลบ) หรือ 401; token ของ customer → 403

### F-006 · Route admin `/api/users/admin/all` ไม่เช็ค role — Critical
- **Category:** A01:2025 Broken Access Control · API5:2023 BFLA · CWE-862
- **Location:** `src/routes/users.js:22-24` · **Confidence:** Confirmed · **L×I:** H×H — customer ทุกคน (และคนไม่ login ผ่าน F-002); อีเมลของ user ทั้งระบบ
- **Evidence:**
  ```js
  // admin: list all users
  router.get('/admin/all', async (req, res) => {
    const r = await db.query('SELECT id, email, role, created_at FROM users');
    res.json(r.rows);
  ```
- **Impact:** รายชื่ออีเมล + role ของทุกบัญชีรั่วให้ทุกคน (PII จำนวนมาก, ใช้ต่อยอด phishing/credential stuffing และหาเป้าหมายที่เป็น admin)
- **Fix:**
  ```js
  // src/middleware/auth.js
  const requireRole = (role) => (req, res, next) =>
    req.user && req.user.role === role ? next() : res.status(403).json({ error: 'forbidden' });
  // src/routes/users.js
  router.get('/admin/all', requireRole('admin'), async (req, res) => { /* ... */ });
  ```
  role ใน token เชื่อได้หลังแก้ F-001 + F-008 เท่านั้น; สำหรับงาน admin ควรอ่าน role สดจาก DB เพราะ token อยู่ได้ 30 วัน (F-024)
- **Verify:** token ของ customer → `GET /api/users/admin/all` ได้ 403; ไม่มี token → 401

### F-007 · SSRF: `POST /api/tools/preview` ให้ server เรียก URL อะไรก็ได้ — Critical
- **Category:** A01:2025 Broken Access Control · API7:2023 SSRF · API10:2023 · API5:2023 · CWE-918
- **Location:** `src/routes/tools.js:7-9` · **Confidence:** Confirmed · **L×I:** H×H — เรียกได้โดยไม่ login (F-002); เข้าถึงเครือข่ายภายใน/cloud metadata
- **Evidence:**
  ```js
  // "so the admin UI can show a link preview" — but no role check
  router.post('/preview', async (req, res) => {
    const resp = await fetch(req.body.url);           // any scheme/host, follows redirects, no timeout
    const html = await resp.text();                   // unbounded body
    const title = (html.match(/<title>(.*?)<\/title>/i) || [])[1] || '';
  ```
- **Impact:** server ส่งคำขอไปยัง host ภายใน (localhost, Postgres, service ใน VPC) หรือ cloud metadata endpoint (`.env` บ่งว่าใช้ AWS) แล้วคืน `<title>` ของหน้าภายใน; ผลสำเร็จ/ล้มเหลวและเวลาตอบใช้สแกน port ภายในได้; URL ที่ตอบช้าหรือใหญ่มากทำให้ worker ค้าง
- **Fix:**
  ```js
  const { useAgent } = require('request-filtering-agent');   // >= 2.0.0: blocks private/link-local IPs after DNS
  const ALLOWED = new Set(['shop.example.com']);              // your real product-page hosts
  router.post('/preview', requireRole('admin'), async (req, res, next) => {
    let u; try { u = new URL(String(req.body.url)); } catch { return res.status(400).end(); }
    if (u.protocol !== 'https:' || !ALLOWED.has(u.hostname)) return res.status(400).json({ error: 'url not allowed' });
    try {
      const resp = await fetch(u.href, { agent: useAgent(u.href), redirect: 'manual', timeout: 5000, size: 1_000_000 });
      // ...parse title as before
    } catch (e) { next(e); }
  });
  ```
  บน AWS ให้บังคับ IMDSv2 (`--http-tokens required`) เป็นชั้นป้องกันเพิ่ม
- **Verify:** test: `url` ที่ชี้ `127.0.0.1`, `169.254.169.254` หรือ host นอก allowlist → 400 และ canary listener บน localhost ไม่ได้รับ request

### F-008 · Mass assignment: ลูกค้าตั้ง `role` ของตัวเองเป็น admin ได้ผ่าน `PUT /api/users/me` — Critical
- **Category:** A08:2025 Software or Data Integrity Failures · API3:2023 BOPLA · CWE-915
- **Location:** `src/routes/users.js:13-16` · **Confidence:** Confirmed · **L×I:** H×H — user ใดก็ได้, request เดียว; privilege escalation
- **Evidence:**
  ```js
  const updated = _.merge(current, req.body);
  await db.query(
    'UPDATE users SET email=$1, name=$2, role=$3 WHERE id=$4',
    [updated.email, updated.name, updated.role, req.user.id]
  );
  ```
- **Impact:** field `role` ใน body ถูกเขียนลง DB ตรง ๆ → login ใหม่ได้ token ที่เป็น admin และผ่าน role check ที่จะเพิ่มใน F-006/F-007 ทันที; เปลี่ยนอีเมลได้โดยไม่ต้องยืนยัน. (ตรวจ source ของ lodash 4.17.15 แล้ว: `_.merge` กัน key `__proto__`/`constructor` ไว้ จึงไม่นับ prototype pollution ที่บรรทัดนี้)
- **Fix:** รับเฉพาะ field ที่อนุญาต และไม่ใช้ `_.merge` กับ `req.body` (ถอด `lodash` ออกได้เลย)
  ```js
  router.put('/me', async (req, res) => {
    const { name, email } = req.body;                       // allowlist — role is never client-writable
    if ([name, email].some((v) => v !== undefined && typeof v !== 'string')) return res.status(400).end();
    const r = await db.query(
      'UPDATE users SET name = COALESCE($1, name), email = COALESCE($2, email) WHERE id = $3 RETURNING id, email, name',
      [name, email, req.user.id]);
    res.json(r.rows[0]);
  });
  ```
- **Verify:** test: `PUT /api/users/me` ที่มี `role` ใน body → role ใน DB ยังเป็น `customer`

### F-009 · Checkout เชื่อราคาที่ client ส่งมา (ตั้งราคา 0 หรือติดลบได้) — Critical
- **Category:** A06:2025 Insecure Design · API6:2023 Sensitive Business Flows · CWE-602, CWE-840
- **Location:** `src/routes/orders.js:21-25` · **Confidence:** Confirmed (ผลต่อการเก็บเงินขึ้นกับระบบ payment นอก repo) · **L×I:** H×H — user ใดก็ได้; payment abuse
- **Evidence:**
  ```js
  const { productId, quantity, price } = req.body;
  const total = price * quantity;
  const r = await db.query(
    'INSERT INTO orders(user_id, product_id, quantity, total) VALUES ($1,$2,$3,$4) RETURNING *',
  ```
- **Impact:** ลูกค้ากำหนด `price` และ `quantity` เอง (0, ติดลบ, ทศนิยม, ไม่ใช่ตัวเลข) → `total` ผิด/ติดลบ/NaN; ถ้า payment หรือ fulfilment ใช้ `orders.total` คือได้สินค้าราคาที่ตัวเองตั้ง
- **Fix:** คำนวณราคาจากตาราง product บน server ใน statement เดียว (ปรับชื่อตาราง/column ตาม schema จริง)
  ```js
  const productId = Number.parseInt(req.body.productId, 10);
  const quantity = Number.parseInt(req.body.quantity, 10);
  if (!Number.isInteger(productId) || !Number.isInteger(quantity) || quantity < 1 || quantity > 100)
    return res.status(400).json({ error: 'invalid input' });
  const r = await db.query(
    `INSERT INTO orders(user_id, product_id, quantity, total)
     SELECT $1, p.id, $2, p.price * $2 FROM products p WHERE p.id = $3
     RETURNING id, product_id, quantity, total`, [req.user.id, quantity, productId]);
  if (!r.rows[0]) return res.status(404).end();
  ```
- **Verify:** test: checkout ที่ส่ง `price: 0` → `total` ที่บันทึก = ราคาสินค้าใน DB × quantity; `quantity` ≤ 0 → 400

### F-010 · Secret อยู่ใน repo: JWT secret fallback แบบ hard-code และ `.env` ถูก commit เข้า git — High
- **Category:** A07:2025 Authentication Failures · API2:2023 · CWE-798, CWE-321 (tag: A04)
- **Location:** `src/config.js:2`, `.env:1-3` (tracked ตั้งแต่ commit 618a611; `.gitignore` มีแค่ `node_modules`; `Dockerfile:3` copy เข้า image) · **Confidence:** Confirmed (อยู่ใน git) / Needs manual verification (คีย์ยังใช้งานได้หรือไม่) · **L×I:** M×H — ขึ้นกับว่า prod ตั้ง `JWT_SECRET` หรือไม่; ถ้าใช้ fallback = ปลอม token ได้ทุก user
- **Evidence:**
  ```
  JWT_SECRET: process.env.JWT_SECRET || 'secr****',   // src/config.js:2 — weak string fallback
  DATABASE_URL=post****                               // .env:1 — Postgres URL with user + password
  AWS_ACCESS_KEY_ID=AKIA****                          // .env:2 — AWS access key ID
  AWS_SECRET_ACCESS_KEY=wJal****                      // .env:3 — AWS secret access key
  ```
- **Impact:** `.env` ไม่มี `JWT_SECRET` และโปรเจกต์ไม่มี `dotenv` → ถ้า deploy ลืมตั้งค่า token จะถูกเซ็นด้วย secret ที่อยู่ใน repo และยังปลอมได้แม้แก้ F-001 แล้ว. ใครที่เห็น repo หรือ Docker image ได้ credential DB/AWS. ค่า AWS ดูเหมือน placeholder ตามตัวอย่างในเอกสาร AWS และ DB ชี้ `localhost` — ถ้าเป็นคีย์จริงให้ถือเป็น **Critical** และ rotate ทันที
- **Fix:**
  ```js
  // src/config.js — fail fast, no fallback
  const JWT_SECRET = process.env.JWT_SECRET;
  if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('JWT_SECRET must be set (>= 32 random chars)');
  module.exports = { JWT_SECRET, PORT: process.env.PORT || 3000 };
  ```
  แล้ว `git rm --cached .env`, เพิ่ม `.env` ใน `.gitignore` และ `.dockerignore`, rotate รหัส DB (และ deactivate AWS key ใน IAM ถ้าเป็นของจริง), เก็บ secret ใน secret manager ของที่ deploy; ล้าง history (`git filter-repo`) หลัง rotate แล้วเท่านั้น
- **Verify:** แอปไม่ยอม start เมื่อไม่ตั้ง `JWT_SECRET`; `git ls-files .env` ว่าง; gitleaks ใน CI ผ่าน

### F-011 · เก็บรหัสผ่านเป็น MD5 ไม่มี salt — High
- **Category:** A04:2025 Cryptographic Failures · API2:2023 · CWE-916, CWE-759
- **Location:** `src/routes/auth.js:14` (+1 similar: `src/routes/auth.js:22`) · **Confidence:** Confirmed · **L×I:** M×H — ต้องได้ hash มาก่อน (ซึ่ง F-003/F-012 ทำให้ง่าย); รหัสผ่านของ user ทุกคน
- **Evidence:**
  ```js
  const hash = crypto.createHash('md5').update(password).digest('hex');
  ```
- **Impact:** MD5 ไม่มี salt ถูก crack ด้วย GPU/rainbow table ได้เร็วมาก และรหัสเดียวกันให้ hash เดียวกัน → hash ที่รั่วกลายเป็นรหัสผ่านจริงของ user ส่วนใหญ่ (ซึ่งมักใช้ซ้ำกับเว็บอื่น)
- **Fix:**
  ```js
  const argon2 = require('argon2');                          // argon2id, defaults m=64MiB t=3 p=4
  const hash = await argon2.hash(password, { type: argon2.argon2id });   // register
  const ok = await argon2.verify(user.password_hash, password);          // login
  ```
  hash MD5 เดิม: ห่อเป็น `argon2id(md5)` ทันที แล้ว rehash ตรงเมื่อ user login ครั้งถัดไป
- **Verify:** row ใหม่ใน `users.password_hash` ขึ้นต้นด้วย `$argon2id$`; test login ของ user ที่ migrate แล้วยังผ่าน

### F-012 · `/api/users/me` ส่ง `password_hash` และ `reset_token` กลับไปให้ client — High
- **Category:** A01:2025 Broken Access Control · API3:2023 BOPLA · CWE-200, CWE-359
- **Location:** `src/routes/users.js:7-8` (+1 similar: response ของ `PUT /me` ที่ `src/routes/users.js:18`) · **Confidence:** Confirmed · **L×I:** H×M — user ใดก็ได้; ลำพังเป็นข้อมูลของตัวเอง แต่รวมกับ F-001 ได้ของทุกคน
- **Evidence:**
  ```js
  const r = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
  res.json(r.rows[0]); // includes password_hash, role, reset_token
  ```
- **Impact:** `reset_token` ใน response = ใครได้ response นี้ (ผ่าน F-001, XSS F-013, proxy/log) ก็ reset รหัสผ่านบัญชีนั้นได้; `password_hash` แบบ MD5 crack ง่าย (F-011)
- **Fix:**
  ```js
  const r = await db.query('SELECT id, email, name, role, created_at FROM users WHERE id = $1', [req.user.id]);
  res.json(r.rows[0]);
  ```
  `PUT /me` ใช้ `RETURNING id, email, name` ตาม F-008; ควรระบุ column แทน `SELECT *` ทุกที่ที่ส่งให้ client
- **Verify:** snapshot test: body ของ `GET`/`PUT /api/users/me` ไม่มี key `password_hash` และ `reset_token`

### F-013 · DOM XSS ในหน้า `public/index.html` (พารามิเตอร์ `q` เข้า `innerHTML`) — High
- **Category:** A05:2025 Injection · CWE-79
- **Location:** `public/index.html:11-12` · **Confidence:** Confirmed · **L×I:** M×H — เหยื่อต้องเปิดลิงก์ที่ถูกสร้าง; script รันบน origin เดียวกับ API
- **Evidence:**
  ```js
  const q = new URLSearchParams(location.search).get('q') || '';
  document.getElementById('app').innerHTML = '<h1>Results for ' + q + '</h1>';
  ```
- **Impact:** ค่า `q` ที่มี HTML markup ถูก render เป็น HTML จริง → script ของผู้โจมตีรันบน origin ของ API ซึ่งอ่าน token ที่ frontend เก็บใน `localStorage`/`sessionStorage` และเรียก API ในนามเหยื่อได้
- **Fix:**
  ```js
  const h1 = document.createElement('h1');
  h1.textContent = 'Results for ' + q;
  document.getElementById('app').replaceChildren(h1);
  ```
  และเพิ่ม CSP (F-020) เป็นชั้นป้องกันที่สอง
- **Verify:** DOM test: `q` ที่มี HTML tag → แสดงเป็นข้อความตรงตัว และ `#app` มี `<h1>` เดียวที่ไม่มี child element

### F-014 · Log รหัสผ่านแบบ plaintext ทุกครั้งที่ login — High
- **Category:** A09:2025 Security Logging & Alerting Failures · CWE-532, CWE-117
- **Location:** `src/routes/auth.js:10` · **Confidence:** Confirmed · **L×I:** M×H — ต้องเข้าถึง log ได้; รหัสผ่านจริงของทุกคนที่ login
- **Evidence:**
  ```js
  console.log('login attempt', email, password);
  ```
- **Impact:** รหัสผ่าน plaintext ไปอยู่ใน stdout → Docker logs / log platform ที่มักมีคนเข้าถึงมากกว่า DB และเก็บนานกว่า; `email` ไม่ถูก sanitize จึงแทรกบรรทัดปลอมใน log แบบ line-based ได้
- **Fix:**
  ```js
  // never log credentials; log the outcome as structured data (e.g. pino)
  logger.info({ event: 'auth.login', outcome: ok ? 'success' : 'failure', userId: user?.id, ip: req.ip });
  ```
  ถ้าเคยรันกับ user จริงแล้ว ให้ลบ log เก่าที่มีรหัสผ่านและพิจารณาบังคับ reset password
- **Verify:** test ที่ดัก stdout ระหว่าง `POST /api/auth/login` → ไม่มีค่า password ปรากฏ

### F-015 · Dependencies และ runtime ล้าสมัย: express 4.17.1 (qs 6.7.0), jsonwebtoken 8.5.0, Node 14 EOL — High
- **Category:** A03:2025 Software Supply Chain Failures · API8:2023 · CWE-1395, CWE-1104
- **Location:** `package.json:8-13`, `package-lock.json` (`node_modules/qs` 6.7.0), `Dockerfile:1` · **Confidence:** Likely (ตาม advisory; reachability ตรวจจากโค้ด) · **L×I:** CVSS-B 7.5 — qs ถูกเรียกจากทุก request ที่ไม่ต้อง login
- **Evidence:** (`npm audit --omit=dev`: 7 high, 3 low ใน 10 packages — รายละเอียดใน `scanner-findings.md`)
  ```
  express 4.17.1  -> qs 6.7.0: GHSA-hrpp-h998-j3pp (CVE-2022-24999, 7.5)  REACHABLE: query parser runs on every request
  jsonwebtoken 8.5.0: GHSA-8cf7-32gw-wr33, GHSA-qwph-4952-7xr6, GHSA-hjrf-2m68-5959  reached once F-001 adds jwt.verify
  qs DoS GHSA-6rw7/-w7fw/-4mjr (reachable); send/serve-static GHSA-m6fv/-cm22 (Low, via express.static)
  lodash 4.17.15, node-fetch 2.6.0, path-to-regexp, body-parser: not reachable in current code (Appendix A)
  FROM node:14   # EOL since 2023-04-30, no security fixes
  ```
- **Impact:** query string ที่ถูกสร้างเฉพาะทำให้ process ของ Node ค้างได้จาก request เดียวโดยไม่ต้อง login (DoS); `jsonwebtoken` <9 มีค่า default ของ `verify` ที่ไม่ปลอดภัย จึงต้อง upgrade ก่อนแก้ F-001; Node 14 ไม่ได้รับ patch (HTTP parser, OpenSSL) อีกแล้ว
- **Fix:**
  ```bash
  npm install express@^4.22.3 jsonwebtoken@^9.0.3 node-fetch@^2.7.0
  npm uninstall lodash            # only used by the _.merge removed in F-008
  # Dockerfile: FROM node:24-slim (current LTS), pinned by digest
  ```
  upgrade Node แล้ว F-016 จะกลายเป็น process crash — ต้องแก้ใน PR เดียวกัน
- **Verify:** `npm audit --omit=dev` ไม่มี High/Critical; `docker run <image> node --version` ≥ 24

### F-016 · Async handler ไม่จับ error: request เดียวทำให้ API ค้าง/ล่มทั้ง process — High
- **Category:** A10:2025 Mishandling of Exceptional Conditions · API4:2023 · CWE-248, CWE-755
- **Location:** `src/routes/orders.js:6` (+9 similar: ทุก `async` handler ใน `auth.js:8,20`, `orders.js:13,20`, `users.js:6,11,22`, `tools.js:6`, `legacy.js:6`) · **Confidence:** Likely · **L×I:** H×M — ไม่ต้อง login; ปัจจุบัน request ค้าง, หลัง upgrade Node คือ API down ทั้งตัว
- **Evidence:**
  ```js
  router.get('/', async (req, res) => {        // Express 4 ignores the rejected promise
    const limit = req.query.limit || 20;
    const r = await db.query('... LIMIT ' + limit, [req.user.id]);   // req.user undefined without a token
  ```
- **Impact:** เรียก `/api/orders` โดยไม่มี token (`req.user` ว่างจาก F-002), register ด้วย email ซ้ำหรือไม่มี password, DB ล่ม, URL ผิดใน preview → promise reject ที่ไม่มีใครจับ. Node 14: response ไม่ถูกส่ง request ค้างจน timeout; Node ≥15 (default `--unhandled-rejections=throw`) process ตายทั้งตัว
- **Fix:**
  ```js
  const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  router.get('/', ah(async (req, res) => { /* ... */ }));   // wrap every async handler (or move to Express 5)
  ```
- **Verify:** test: mock `db.query` ให้ reject → ได้ 500 JSON และ process ยังทำงาน; ไม่มี token → 401

### Medium / Low / Info

| ID | Sev | Title | Category · CWE | Location | Fix (one line) |
|---|---|---|---|---|---|
| F-017 | Medium | CORS สะท้อนทุก origin พร้อม `credentials: true` | A02:2025 · API8 · CWE-942 | `src/server.js:8` | `cors({ origin: ['https://<your-shop-domain>'], credentials: false })` — ตอนนี้ใช้ Bearer header จึงไม่ต้องเปิด credentials |
| F-018 | Medium | Error handler ส่ง `err.message` + `err.stack` ให้ client (เช่น JSON body ที่ parse ไม่ได้) | A10:2025 · API8 · CWE-209 | `src/server.js:19` | log `err` ฝั่ง server แล้วตอบ `{ error: 'internal error' }` (ใช้ `err.status` ถ้าเป็น 4xx จาก body-parser) |
| F-019 | Medium | ไม่มี rate limit / lockout ที่ login และ register (brute force, สร้างบัญชีจำนวนมาก) | A07:2025 · API2 · API6 · CWE-307 | `src/routes/auth.js:8,20` | `express-rate-limit` ต่อ IP + ต่อ email ที่ `/api/auth/*` (เช่น 5 ครั้ง/15 นาที) และ backoff เมื่อผิดซ้ำ |
| F-020 | Medium | ไม่มี security headers (CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`) และมี `X-Powered-By: Express` | A02:2025 · API8 · CWE-693 | `src/server.js:7` | `app.use(require('helmet')())` + CSP ที่ไม่อนุญาต inline script (ย้าย script ใน `index.html` ออกเป็นไฟล์) |
| F-021 | Medium | ไม่มีเพดานทรัพยากร: `limit` ไม่จำกัด, export ไม่มี pagination, outbound fetch ไม่มี timeout/size | A06:2025 · API4 · API10 · CWE-770 | `src/routes/orders.js:7`, `src/routes/legacy.js:7`, `src/routes/tools.js:7-8` | cap `limit` ≤ 100 (F-003), ลบ/แบ่งหน้า export (F-005), `timeout` + `size` ใน fetch (F-007) |
| F-022 | Medium | Dockerfile: `COPY . .` ไม่มี `.dockerignore` (ใส่ `.env` + `.git` ใน image), `npm install` รวม devDeps, รันเป็น root | A02:2025 · CWE-250, CWE-538 | `Dockerfile:3-6` | เพิ่ม `.dockerignore` (`.env`, `.git`, `node_modules`, `.security-review`), `npm ci --omit=dev`, `USER node` |
| F-023 | Medium | โหลด `axios@0.21.0` จาก CDN โดยไม่มี SRI (และเป็นเวอร์ชันที่มีช่องโหว่ แต่หน้านี้ไม่ได้ใช้ axios เลย) | A08:2025 · CWE-830 (tag: A03) | `public/index.html:6` | ลบ `<script>` นี้; ถ้าต้องใช้ให้ bundle เองหรือใส่ `integrity` + `crossorigin` |
| F-024 | Medium | JWT อายุ 30 วัน ไม่มี revoke/logout และ `role` ถูกฝังใน token (ลด role แล้วยังใช้สิทธิ์เดิมได้ 30 วัน) | A07:2025 · API2 · CWE-613 | `src/routes/auth.js:16` | access token ≤ 15–60 นาที + refresh token ที่ revoke ได้; อ่าน role จาก DB สำหรับงาน admin |
| F-025 | Medium | ไม่ log security event (login ล้มเหลว, 401/403, งาน admin) และไม่มี alert | A09:2025 · CWE-778 | ทั้งแอป (`src/routes/auth.js`, `src/middleware/auth.js`) | structured log (pino) สำหรับ auth/authz failure พร้อม request ID แล้วตั้ง alert เมื่อผิดซ้ำ — alerting อยู่นอก repo ต้องยืนยันกับทีม ops |
| F-026 | Low | User enumeration: email ที่ไม่มีได้ 404 "No account with that email" แต่รหัสผิดได้ 401 | A07:2025 · CWE-204 | `src/routes/auth.js:13-15` | ตอบ 401 `{ error: 'invalid credentials' }` เหมือนกันทั้งสองกรณี (และ verify hash หลอกเพื่อให้เวลาเท่ากัน) |
| F-027 | Low | Register ไม่ตรวจ input และไม่มี password policy (รหัสว่าง/สั้นได้; ไม่มี password → exception) | A07:2025 · CWE-521 | `src/routes/auth.js:21-22` | validate schema (เช่น zod): email format, password ≥ 8 ตัว (ASVS 6.2.1) + ตรวจกับรายการรหัสที่รั่ว |
| F-028 | Info | ไม่มี CI, test และ security scanning ใน repo — authz regression จะไม่ถูกจับ | A03:2025 · CWE-1357 | repo root | เพิ่ม CI: `npm audit`/osv-scanner, semgrep, gitleaks + integration test สอง user สำหรับทุก route ที่รับ id |

## 4. Remediation plan

| Priority | Findings | Effort | Action |
|---|---|---|---|
| Now (before deploy) — auth core | F-001, F-002, F-010, F-015 (jsonwebtoken) | S | เขียน `requireAuth` ใหม่ด้วย `jwt.verify` + 401, บังคับ `JWT_SECRET` จาก env, เอา `.env` ออกจาก git และ rotate credential |
| Now (before deploy) — per-route | F-003, F-004, F-005, F-006, F-007, F-008, F-009, F-012 | M | parameterize SQL, ผูก query กับ `user_id`, เพิ่ม `requireRole('admin')`, ลบ legacy export, allowlist field/URL, คำนวณราคาจาก DB, ระบุ column แทน `SELECT *` |
| Now (before deploy) — platform | F-011, F-013, F-014, F-015, F-016 | M | argon2id + migrate hash, แก้ `innerHTML`, เลิก log password, upgrade deps + Node LTS พร้อมห่อ async handler |
| Next sprint | F-017 – F-025 | M | CORS allowlist, generic error, rate limit, helmet/CSP, resource caps, Dockerfile hardening, ลบ CDN script, token อายุสั้น, security logging + alert |
| Backlog / hardening | F-026 – F-028, ASVS 5.0 L2 gaps | S–M | ข้อความ login เดียวกัน, password policy, CI + test |

**Prevent recurrence:** เพิ่ม CI ที่รัน `npm audit --omit=dev` (หรือ osv-scanner), semgrep (`p/owasp-top-ten`, `p/nodejs`) และ gitleaks โดย pin เวอร์ชันของ scanner; pre-commit gitleaks; integration test สอง user (A/B) + customer/admin สำหรับทุก route ที่รับ id หรือเป็น admin; ห้ามใช้ `jwt.decode` เพื่อ auth และห้ามต่อ string เป็น SQL (semgrep rule); ใช้ ASVS 5.0 Level 2 เป็น checklist ก่อนขึ้น production. หลังแก้แล้วควรรัน passive runtime check (headers/CORS/error page) และ two-user authz test บน localhost หรือ staging

## 5. Scope, method and limitations

- **Stack:** Node.js + Express 4.17.1, Postgres ผ่าน `pg` (raw SQL), JWT (`jsonwebtoken`), static HTML · **Entry points reviewed:** 10 API routes + static files (ทั้งหมด) · **Approx. LOC:** 154 (อ่านครบทุกไฟล์)
- **Tools run:** `npm audit` (npm 10.9.7) — ran, 10 vulnerable packages / 25 advisories; semgrep 1.178.0 — FAILED (exit 2, ไม่มี error output; น่าจะดาวน์โหลด rule ไม่ได้) จึงใช้ manual review แทน; gitleaks, osv-scanner, trivy, hadolint — not installed (วิธีติดตั้งใน `scanners.md`). Secret ใน git ตรวจด้วยมือ (history มี 1 commit)
- **Runtime checks:** none — ไม่มีแอปที่รันอยู่ ผลทั้งหมดมาจากการอ่านโค้ด
- **Not covered / needs follow-up:** schema ของ DB (ตาราง `products`, unique constraint ของ email, flow ของ `reset_token` ที่ไม่มี route ใน repo), frontend จริงนอกเหนือจาก `public/index.html` (token เก็บที่ไหน), ค่า env ของ production (`JWT_SECRET`, `NODE_ENV`), TLS/reverse proxy/WAF, IMDS บน AWS, ระบบ payment ที่ใช้ `orders.total`, ระบบ log/alert
- **Dismissed scanner leads:** 16 (ไม่ reachable ในโค้ดปัจจุบัน — Appendix A); 9 ที่เหลือรวมอยู่ใน F-015
- **หมายเหตุ:** `.gitignore` ยังไม่ครอบ `.security-review/` — ควรเพิ่มเพื่อไม่ให้รายงานนี้ถูก commit (รีวิวนี้ไม่ได้แก้ `.gitignore` ให้)

## Appendix A — Dismissed scanner leads
ทุกข้อด้านล่างจะหายไปเองเมื่อ upgrade ตาม F-015 แต่ไม่ถูกนับเป็น finding เพราะโค้ดปัจจุบันไปไม่ถึงส่วนที่มีช่องโหว่

| Tool | Rule | Location | Reason dismissed |
|---|---|---|---|
| npm-audit | GHSA-35jh-r3h4-6jhm, GHSA-r5fr-rjxr-66jc (lodash `_.template`) | `package-lock.json` (lodash 4.17.15) | ไม่มีการเรียก `_.template` |
| npm-audit | GHSA-p6mc-m468-83gw (lodash `zipObjectDeep`/`set`) | lodash 4.17.15 | ใช้แค่ `_.merge` ซึ่งใน 4.17.15 กัน `__proto__`/`constructor` (ตรวจ `safeGet` ใน source แล้ว) |
| npm-audit | GHSA-f23m-r3pf-42rh, GHSA-xxjr-mmjv-4gpg (lodash `_.unset`/`_.omit`), GHSA-29mw-wpgm-hmr9 (ReDoS) | lodash 4.17.15 | ไม่มีการเรียกฟังก์ชันเหล่านี้ |
| npm-audit | GHSA-r683-j2x4-v87g, GHSA-w7rc-rwvf-8q5r | node-fetch 2.6.0 | `tools.js` ไม่ส่ง header ลับและไม่ใช้ option `size` (ปัญหา redirect ครอบโดย F-007 แล้ว) |
| npm-audit | GHSA-9wv6-86v2-598j, GHSA-rhx6-c78j-4q9w, GHSA-37ch-88jc-xwx2 | path-to-regexp (via express) | route มีแค่ `/:id` ไม่มีหลาย parameter ใน segment เดียว |
| npm-audit | GHSA-qwcr-r2fm-qrc7, GHSA-v422-hmwv-36x6 | body-parser (via express) | ไม่ได้เปิด `urlencoded` และไม่ได้ตั้ง `limit` เอง |
| npm-audit | GHSA-rv95-896h-c2vc, GHSA-qw6h-vgh9-j6wx | express 4.17.1 | ไม่มีการเรียก `res.redirect`/`res.location` |
| npm-audit | GHSA-pxg6-pf52-xh8x | cookie (via express) | แอปไม่ได้ตั้ง cookie |

## Appendix B — Files
`inventory.md` · `attack-surface.md` · `scanners.md` · `scanner-findings.md` · `raw/`
