## A05:2025 – Injection
**Edition notes:** Was A03:2021 (#3); drops to **#5** in 2025, still between A04:2025 Cryptographic Failures and A06:2025 Insecure Design. XSS stays merged in here (it was folded in during 2021). The category now maps **37 CWEs** (33 in 2021). Newly mapped: CWE-76, 86, 103, 104, 112, 114, 115, 129, 159, 493, 500. No longer mapped: CWE-75, 87, 100, 138, 184, 471, 652. Stats: 100% of tested apps were tested for some form of injection, and this category has the **most CVEs of any (62,445)**. XSS has >30k CVEs (high frequency, low impact) and SQLi >14k (low frequency, high impact). The official page points to **OWASP LLM Top 10 LLM01:2025 Prompt Injection** for "a related class of injection" in LLM apps. SSTI is covered by the page (it cites PortSwigger SSTI) through CWE-94/917, but CWE-1336 (template engine) is **not** in the mapped list. API Top 10 2023 has **no standalone injection risk** (API8:2019 Injection was dropped). The closest is API10:2023 Unsafe Consumption of APIs, which says data from integrated APIs must be validated and sanitized.

### What it is (issue)
Untrusted data reaches an interpreter (SQL/ORM, NoSQL, OS shell, browser HTML/JS, template engine, expression language, LDAP, XPath, HTTP/mail headers). The interpreter then runs part of that data as commands or code instead of treating it as data. The flaw is almost always data and code mixed in one string, or a framework "escape hatch" that turns off the safe default. Impact ranges from DOM changes in one user's browser (XSS) to reading or changing the whole database, or remote code execution (SQLi, command injection, SSTI, EL injection).

### Root causes
- Queries, commands and markup built by string concatenation, interpolation or `format`, instead of APIs that take code and data separately (bind parameters, argv arrays, auto-escaping templates).
- Escape hatches used for convenience: raw-SQL ORM methods, `shell=True`, `|safe`, `{!! !!}`, `dangerouslySetInnerHTML`, `v-html`, `Html.Raw`, `th:utext`, `template.HTML`.
- Identifiers (table and column names, ORDER BY, sort direction) cannot be bound, so developers concatenate them instead of mapping them through an allowlist.
- "Internal" data is treated as trusted: DB values (second-order injection), headers and cookies, file contents, webhook and third-party API payloads (API10:2023), and **LLM output**.
- Loose typing in JSON bodies: an object or array arrives where a string was expected, which enables Mongo operator injection (`{"$ne": …}`).
- Output encoded for the wrong context (HTML encoding inside JS, URL or CSS contexts), double decoding, or validation before canonicalization.
- User input treated as code: `eval`, `new Function`, SpEL/OGNL/EL evaluation, `render_template_string(user)`, `Handlebars.compile(user)`, or a user-controlled view name.
- Shelling out where a library call would do. Missing defense in depth: no CSP, and a DB account with DDL or superuser rights.

### Key CWEs
All 37 mapped: 20, 74, 76, 77, 78, 79, 80, 83, 86, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 103, 104, 112, 113, 114, 115, 116, 129, 159, 470, 493, 500, 564, 610, 643, 644, 917. ★ = most relevant for web/API developers.
- ★ CWE-89 Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection'); CWE-564 SQL Injection: Hibernate (ORM/HQL)
- ★ CWE-79 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting'); CWE-80, CWE-83 (script in tags and attributes)
- ★ CWE-78 OS Command Injection; CWE-77 Command Injection; ★ CWE-88 Argument Injection
- ★ CWE-94 Improper Control of Generation of Code ('Code Injection'); CWE-95 Eval Injection
- ★ CWE-917 Expression Language Injection (SpEL/OGNL/EL; also relevant to SSTI)
- ★ CWE-74 Injection (parent class, used for NoSQL operator injection); CWE-116 Improper Encoding or Escaping of Output
- ★ CWE-90 LDAP Injection; CWE-643 XPath Injection; CWE-91 XML Injection
- CWE-93 CRLF Injection; CWE-113 HTTP Response Splitting; CWE-20 Improper Input Validation; CWE-470 Unsafe Reflection; CWE-98 PHP File Inclusion

### How to detect — code review
**Stack-agnostic signals**
- Map **sources** (params, body, headers, cookies, uploaded files, DB rows written by users, queue and webhook messages, third-party API responses, LLM outputs) to **sinks**: raw SQL and ORM "raw" methods, NoSQL filters, `exec`/`system`/shell, HTML and DOM writers, template compile/render, `eval` and expression parsers, LDAP/XPath filters, response and mail headers, CSV/XLSX exports (ASVS 1.2.10).
- Where to look: repositories/DAOs, `*Mapper.xml`, stored procedures and migrations with dynamic SQL (`EXEC(`, `sp_executesql` + concatenation), controllers that return HTML strings, templates (`*.html`, `*.jinja*`, `*.blade.php`, `*.cshtml`, `*.razor`, `*.vue`, `*.svelte`, `*.tsx`), jobs and scripts that shell out, and CI workflows (`${{ github.event.* }}` inside `run:`).
- Config: is a CSP header present and strict? Is template autoescape on? Is Mongo `security.javascriptEnabled` set? Does the DB user have least privilege? Is `helmet` or an equivalent header middleware in place?
- Broad first pass (any language). It flags SQL keywords inside strings that are also interpolated or concatenated:
```
rg -nP -i '\b(select|insert\s+into|update|delete\s+from)\b[^\n]*\b(from|into|set|where|values)\b[^\n]*("\s*\+\s*\w|\x27\s*\+\s*\w|\$\{|\bf"|\bf\x27|\.format\(|fmt\.Sprintf|String\.format|\$")'
rg -nP '["\x27]\(&?\(?\w+=["\x27]\s*(\+|\.)'                                  # LDAP filter concat, e.g. "(uid=" + user
rg -nP '\$\{\{\s*github\.(event\.(issue|pull_request|comment|review|head_commit|discussion)|head_ref)' .github/workflows   # Actions script injection
```
**Node (Express / NestJS / Next.js)**: use `-t js -t ts`
```
rg -nP '\.(query|execute|raw|whereRaw|orWhereRaw|havingRaw|orderByRaw|joinRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(`[^`]*\$\{|["\x27][^"\x27]*["\x27]\s*\+)'
rg -nP '\$(queryRawUnsafe|executeRawUnsafe)\b|Prisma\.raw\(|[sS]equelize\.literal\(|\.(where|andWhere|orWhere|orderBy|having)\(\s*`[^`]*\$\{'   # TypeORM/Knex
rg -nP '\$where|\$function|\$accumulator|\.mapReduce\(|\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteMany|countDocuments)\(\s*req\.(body|query|params)\b'
rg -nP '\{\s*\w+\s*:\s*req\.(body|query)\.\w+\s*[,}]'     # value may be an object → Mongo operator injection unless type-checked
rg -nP '\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^,)]*\+)|shell\s*:\s*true'
rg -nP 'dangerouslySetInnerHTML|\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|v-html|\{@html|bypassSecurityTrust|\beval\s*\(|new\s+Function\s*\('
rg -nP 'res\.(send|write|end)\s*\(\s*(`[^`]*\$\{|["\x27][^"\x27]*<)'   # Express res.send(string) defaults to text/html
rg -nP '(ejs|pug|nunjucks|[hH]andlebars)\.(render|compile|renderString)\s*\(\s*req\.'  # SSTI: user input AS template
```
Also check `href={user.url}` and `router.push(userUrl)`. React 16.9–18 only **warns** on `javascript:` URLs; React 19 swaps them for a URL that throws. `data:` and non-React sinks are not covered, so validate the scheme anyway. The Next.js JSON-LD pattern must escape `<` (`.replace(/</g,'\\u003c')`).

**Python (Django / FastAPI / Flask)**: use `-t py`
```
rg -nP '\.(execute|executemany|executescript|raw|extra)\s*\(\s*(f["\x27]|["\x27][^"\x27]*["\x27]\s*(%\s*[\w(]|\.format\(|\+))'
rg -nP 'RawSQL\(|\.extra\(|text\(\s*f["\x27]|literal_column\(|session\.execute\(\s*f["\x27]'
rg -nP 'shell\s*=\s*True|os\.(system|popen)\(|subprocess\.(getoutput|getstatusoutput)\(|\b(eval|exec)\s*\('
rg -nP 'mark_safe\(|Markup\(|render_template_string\(|\.from_string\(|autoescape\s*=\s*False|\$where'
rg -nP '\|\s*safe\b|\{%-?\s*autoescape\s+(off|false)' -g '*.{html,jinja,jinja2,j2}'
```
**Java (Spring Boot)**: use `-t java`
```
rg -nP -i '"\s*(select|insert|update|delete|from|where|order by)\b[^"]*"\s*\+'           # SQL/JPQL/HQL built by +
rg -nP '(createQuery|createNativeQuery|prepareStatement|executeQuery|query|queryForList|update)\s*\(\s*(String\.format|\w+\s*\+)'
rg -n '\$\{' -g '*Mapper.xml'; rg -nP '@(Select|Update|Delete|Insert)\([^)]*\$\{'     # MyBatis ${} = raw substitution
rg -nP 'Runtime\.getRuntime\(\)\.exec\(|new\s+ProcessBuilder\(|"(/bin/)?(ba)?sh"\s*,\s*"-c"|"cmd(\.exe)?"\s*,\s*"/c"'
rg -nP 'SpelExpressionParser|\.parseExpression\(|createValueExpression|Velocity\.evaluate|ScriptEngineManager|return\s+"[\w/:-]*"\s*\+\s*\w'  # last = user-built view name (Spring view manipulation)
rg -nP 'th:utext|\[\(\$\{|escapeXml\s*=\s*"false"|<%=' -g '*.{html,jsp,jspx}'
```
**Go**: use `-t go`
```
rg -nP '\.(Query|QueryRow|QueryContext|QueryRowContext|Exec|ExecContext|Raw|Where|Or|Not|Order|Group|Having|Joins|Select|Table)\s*\(\s*(ctx\s*,\s*)?(fmt\.Sprintf\(|"[^"]*"\s*\+)'
rg -nP 'exec\.Command(Context)?\(\s*(ctx\s*,\s*)?"(/bin/)?(ba|z)?sh"\s*,\s*"-c"'
rg -nP 'template\.(HTML|JS|JSStr|URL|HTMLAttr|CSS|Srcset)\(|"text/template"|fmt\.Fprintf\(\s*w\s*,\s*"[^"]*<'
```
**PHP (Laravel)**: use `-t php`
```
rg -nP '(DB::(select|insert|update|delete|statement|unprepared|raw)|->(whereRaw|orWhereRaw|havingRaw|orderByRaw|selectRaw|groupByRaw))\s*\(\s*("[^"]*\$|[^,)]*\.\s*\$)'
rg -nP '->(orderBy|groupBy|select|pluck)\(\s*(\$request->|request\()'           # column names from user (PDO can't bind them)
rg -nP '\b(shell_exec|system|passthru|proc_open|popen|pcntl_exec|exec)\s*\(|fromShellCommandline\(|\beval\s*\('
rg -n '\{!!' -g '*.blade.php'; rg -nP 'Blade::render\(|echo\s+\$_(GET|POST|REQUEST|COOKIE)'
```
**.NET (ASP.NET Core)**: use `-t cs`, plus `*.cshtml`/`*.razor` for markup
```
rg -nP '(FromSqlRaw|ExecuteSqlRaw\w*|SqlQueryRaw)\s*\(\s*(\$@?"|"[^"]*"\s*\+|string\.Format)'
rg -nP 'new\s+(Sql|Npgsql|MySql|Sqlite)Command\(\s*(\$"|"[^"]*"\s*\+)|CommandText\s*=\s*(\$"|"[^"]*"\s*\+)'
rg -nP '\.(Query|QueryAsync|QueryFirst\w*|QuerySingle\w*|Execute|ExecuteAsync)(<[^>]+>)?\(\s*(\$"|"[^"]*"\s*\+)'   # Dapper
rg -nP 'FileName\s*=\s*"(cmd(\.exe)?|/bin/(ba)?sh|powershell|pwsh)"|Arguments\s*=\s*(\$"|"[^"]*"\s*\+)|\.Filter\s*=\s*(\$"|"[^"]*"\s*\+)'
rg -nP '@Html\.Raw\(|new\s+HtmlString\(|\(MarkupString\)' -g '*.{cs,cshtml,razor}'
```
**LLM features (prompt injection; OWASP LLM Top 10). The IDs below are 2025 IDs. In the Aug 2026 edition they are LLM01 Prompt Injection, LLM10 Improper Output Handling and LLM03 Excessive Agency; see references/category-map.md.** Find call sites (`rg -nP -i 'openai|anthropic|langchain|llamaindex|generateText|streamText|chat\.completions|messages\.create|tool_calls'`). Then check three things. (a) Untrusted content (user text, retrieved docs, web pages, emails) must not be concatenated into system prompts without separation (LLM01). (b) Model output must not flow into SQL, shell, `eval`, HTML or markdown renderers, or URLs without the same treatment as user input (LLM05 Improper Output Handling). (c) Tools the model can call must be least-privilege, and side-effecting actions must need human approval (LLM06 Excessive Agency).

**False-positive notes**
- These are parameterized and fine: Prisma `` $queryRaw`…${x}` `` / `Prisma.sql` / `Prisma.join`; EF Core `FromSql($"…{x}")`, `FromSqlInterpolated`, `ExecuteSql($"…")`, and `FromSqlRaw("… {0}", x)` (positional parameters); Python `execute("… %s", (x,))` (the `%s` is a placeholder, not `%` formatting); MyBatis `#{}`; Laravel `whereRaw('a = ?', [$x])`; GORM `Where("name = ?", x)`.
- Concatenating **constants or allowlist-mapped identifiers** (e.g. `ORDER BY ${SORT_MAP[key]}`) is safe. So are raw queries in migrations and tests that use only literals.
- Angular `[innerHTML]` is sanitized by Angular. Only `bypassSecurityTrust*` is a real hole. React `{value}` and Blade/Jinja/Razor/Thymeleaf `th:text` default output are escaped.
- `dangerouslySetInnerHTML`/`v-html` fed by DOMPurify output, or JSON-LD with `<` escaped, is acceptable.
- Go `exec.Command("git", "log", arg)` and Node `execFile`/`spawn` without `shell:true` involve no shell, but still check argument injection (a value starting with `-`). Java `Runtime.exec(String)` does not use a shell, but it tokenizes the string, so argument injection is still possible.
- Mongoose with `sanitizeFilter: true`, or a schema validator (zod/Joi/class-validator/pydantic) that forces `string`, neutralizes operator injection. In Express 5 the default query parser is `simple` (Express 4 used `extended`), so `?a[$ne]=` no longer builds objects. JSON bodies still can.
- Header CR/LF: Node (`ERR_INVALID_CHAR`) and Django (`BadHeaderError`) reject newlines in header values. Flag only custom protocol, mail or raw socket code, or older stacks.

### How to detect — runtime (safe, own app only)
Run only against localhost or staging, with test accounts and test data. Each probe below is a harmless marker that checks input is treated as data. None of them is an exploit.
- **SQL smoke test:** send a lone quote in a filter or sort param (e.g. `?id=1'` or `?sort=name'`). Expect a 400/404 or an ignored value. A 500 or a DB error string (`syntax error`, `SQLSTATE`, `ORA-`, `psycopg2`) means the value reached SQL unparameterized. Tail the server logs while you do this.
- **Identifier allowlist:** send `?sort=not_a_column`. Expect it to be rejected or to fall back to the default. An error naming the column means the value is concatenated into ORDER BY.
- **NoSQL type check:** POST a JSON body where a string field (e.g. `email`) is an object instead, like `{"email": {"k": "v"}}`. Expect a 400 from schema validation. A 200 or 500 means the handler takes non-string types.
- **HTML encoding:** store and then view a harmless marker such as `zz<b>marker</b>zz`. The page source should show `&lt;b&gt;`. If the text renders bold, output is not encoded in that context.
- **Headers:** check `Content-Security-Policy` exists and has no `'unsafe-inline'` / `'unsafe-eval'` in `script-src` (curl -sI).
- **Command paths:** for features that take a filename or host, send a value that starts with `-` or contains a space. Expect validation to reject it. Never send shell metacharacter chains.
- Watch the app logs during all probes. Parser or driver errors in logs = the sink saw raw input.

### Tools
- **Semgrep CE**: `semgrep scan --config p/owasp-top-ten --config p/default --sarif -o semgrep.sarif` (language packs: `p/javascript`, `p/typescript`, `p/react`, `p/python`, `p/django`, `p/flask`, `p/java`, `p/golang`, `p/php`, `p/csharp`). Taint-mode rules cover SQLi, XSS, command injection and SSTI. Check rule names at semgrep.dev/r because the registry changes.
- **CodeQL** (free for public repos / local CLI): queries `js/sql-injection`, `js/xss`, `js/command-line-injection`, `py/sql-injection`, `py/command-line-injection`, `py/reflective-xss`, `java/sql-injection`, `go/sql-injection`, `cs/sql-injection`.
- **Bandit** (Python): B608 (SQL string building), B602/B605 (shell), B701/B703 (Jinja autoescape / Django mark_safe).
- **gosec** (Go): G201/G202 (SQL string formatting/concat), G204 (subprocess with variable).
- **eslint-plugin-security** / `eslint-plugin-react` (`react/no-danger`), `eslint-plugin-no-unsanitized` (Mozilla) for DOM sinks.
- **Brakeman** (Rails), **Psalm taint analysis** (`psalm --taint-analysis`) for PHP, **SpotBugs + FindSecBugs** for Java.
- **DAST (own app only)**: OWASP ZAP baseline is passive only; active scan rules for SQLi/XSS exist in ZAP but run them only against a disposable local/staging environment.

### Fix / remediation
Primary rule: keep code and data separate. Use bind parameters, argv arrays, auto-escaping templates and allowlists for identifiers. Validate types at the edge with a schema.

**SQL — Node (pg)**
```js
// bad
await db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`);
// good
await db.query('SELECT * FROM orders WHERE id = $1', [req.params.id]);
// identifiers: allowlist map, never raw input
const SORT = { name: 'name', created: 'created_at' };
const col = SORT[req.query.sort] ?? 'created_at';
```
**SQL — Python**
```python
# bad
cur.execute(f"SELECT * FROM users WHERE email = '{email}'")
# good
cur.execute("SELECT * FROM users WHERE email = %s", (email,))
# Django ORM: User.objects.filter(email=email); raw(): User.objects.raw("... WHERE email = %s", [email])
```
**SQL — Java (Spring JDBC / JPA)**
```java
// bad
jdbc.queryForList("SELECT * FROM users WHERE name = '" + name + "'");
// good
jdbc.queryForList("SELECT * FROM users WHERE name = ?", name);
// JPA: @Query("select u from User u where u.name = :name") + @Param("name")
```
**NoSQL (Mongo)**: validate with zod/Joi/pydantic so the field must be a string; enable Mongoose `sanitizeFilter: true`; never pass `req.body` directly as a filter.

**OS command**: prefer a library over shelling out. If you must, pass an argv array with no shell and an allowlist, and put `--` before user values.
```python
# bad
subprocess.run(f"convert {name} out.png", shell=True)
# good
subprocess.run(["convert", "--", safe_name, "out.png"], check=True)
```
```js
// bad
exec(`ping ${host}`);
// good
execFile('ping', ['-c', '1', '--', host]); // plus allowlist/regex on host
```
**XSS**: rely on framework auto-escaping. Remove `dangerouslySetInnerHTML`/`v-html`/`|safe`/`{!! !!}`/`Html.Raw` or feed them only DOMPurify-sanitized HTML. Add a strict CSP (nonce- or hash-based `script-src`, `object-src 'none'`, `base-uri 'none'`). Use `textContent` instead of `innerHTML` in plain JS.

**Templates / expressions**: never compile user input as a template (`render_template_string(user)`, `Handlebars.compile(user)`); use a fixed template with variables. Never evaluate SpEL/OGNL with user input; use `SimpleEvaluationContext` if unavoidable.

**LLM features**: treat model output as untrusted input for every downstream sink; keep untrusted text out of the system prompt; least-privilege tools with human approval for side effects.

**Defense in depth**: least-privilege DB user (no DDL/superuser for the app), strict CSP, centralized input schemas, logging of validation failures (A09).

### Best-practice checklist
- [ ] Every SQL/ORM call uses bind parameters; raw methods are reviewed and use placeholders (ASVS V1.2.4).
- [ ] Dynamic identifiers (sort, column, table) go through an allowlist map.
- [ ] Request bodies and params are validated by a schema with strict types (strings are strings; no unknown keys).
- [ ] No `eval`/`new Function`/dynamic template compile on user or DB data (ASVS V1.3.2, V1.3.7).
- [ ] No shell invocation with user data; argv arrays + allowlists + `--` where a subprocess is unavoidable (ASVS V1.2.5).
- [ ] Template auto-escaping is on everywhere; each raw-HTML escape hatch is justified and sanitized (ASVS V1.2.1, V1.3.1).
- [ ] Strict CSP deployed (nonce/hash; no `unsafe-inline` in `script-src`) (ASVS V3.4.3).
- [ ] Output encoding is context-aware (HTML body, attribute, JS, URL, CSS).
- [ ] LDAP/XPath/CSV-export sinks encode or validate input (ASVS V1.2.6, V1.2.7, V1.2.10); mail input sanitized (V1.3.11).
- [ ] Data from DB, queues, webhooks, third-party APIs and LLMs is treated as untrusted at each sink.
- [ ] App DB account is least-privilege.
- [ ] SAST with taint rules runs in CI on every PR.

### Severity guidance
- **Critical**: unauthenticated SQLi/command injection/SSTI/code injection reachable from the internet, or any injection leading to RCE or full DB read/write.
- **High**: authenticated SQLi or command injection; stored XSS in a page viewed by other users or admins; NoSQL operator injection that bypasses login or authorization.
- **Medium**: reflected/DOM XSS needing user interaction with a strong CSP partly mitigating; injection limited to the attacker's own data; CRLF/header injection without clear exploit path.
- **Low**: raw-SQL with only constant/allowlisted input but no guard rails (maintainability risk); missing CSP as defense in depth only; `dangerouslySetInnerHTML` on sanitized content without a test.

### Sources
- https://owasp.org/Top10/2025/A05_2025-Injection/
- https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Query_Parameterization_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
- https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
- https://genai.owasp.org/llm-top-10/
- https://github.com/OWASP/ASVS (5.0.0, V1 Encoding and Sanitization)
