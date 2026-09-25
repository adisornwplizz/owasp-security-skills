# OWASP Security Skills for Claude Code

A Claude Code plugin that reviews **your own** web app or API against
**OWASP Top 10:2025** and **OWASP API Security Top 10:2023**. It also covers the OWASP LLM Top 10 when the app calls an LLM.
The result is a prioritized report with `file:line` evidence, OWASP/CWE mapping and concrete fixes for your framework.

> 🇹🇭 ภาษาไทย: [ดูด้านล่าง](#ภาษาไทย)

## What it does

- **Maps findings to the current standards.** Top 10:2025 (final, Jan 2026), API Security Top 10:2023 and ASVS 5.0 references. SSRF is filed under A01:2025, and the new A03 (Software Supply Chain) and A10 (Exceptional Conditions) categories are covered.
- **Reviews the whole app.** It builds an attack-surface map, then reviews each category across code, config, dependencies, Dockerfiles, CI and IaC. The heaviest focus is on what scanners miss: authorization (IDOR/BOLA, BFLA, mass assignment), business logic, fail-open error handling and logging.
- **Runs your scanners if you have them.** Supported tools are Semgrep, gitleaks, osv-scanner, trivy, npm/pnpm/yarn audit, govulncheck, bandit, gosec, hadolint, zizmor and checkov. It never installs anything, and every scanner hit is verified against the code before it is reported.
- **Reviews a diff before merge.** `diff main` limits the review to the changes, while still checking context in other files such as middleware order.
- **Checks a running app, safely.** Pass `--url http://localhost:3000` for passive checks of headers, cookies, CORS and error pages. It refuses non-local hosts unless you pass `--allow-remote`.
- **Writes reports people can share.**
  - Secrets are redacted.
  - No exploit payloads, and no proof-of-concept exploits are ever built or run.
  - Critical and High findings get full write-ups with a code fix; Medium and Low findings are listed in a table.
  - A coverage matrix shows the status of every category.
  - The report is written in the user's language.

## Install

**Plugin marketplace (recommended):**

```
/plugin marketplace add adisornwplizz/owasp-security-skills
/plugin install owasp-security@owasp-security-skills
```

**Manual (user-level skill):**

```bash
git clone https://github.com/adisornwplizz/owasp-security-skills.git
mkdir -p ~/.claude/skills
cp -R owasp-security-skills/plugins/owasp-security/skills/owasp-top10-review ~/.claude/skills/
```

## Use

Just ask. For example:

- "Check the security of this project before I deploy"
- "ตรวจ security ตาม OWASP ให้หน่อย"
- "Review the security of branch feature/x against main"

Or call it directly:

```
/owasp-security:owasp-top10-review                    # full repo
/owasp-security:owasp-top10-review diff main          # PR / branch review
/owasp-security:owasp-top10-review --url http://localhost:3000
/owasp-security:owasp-top10-review --quick            # manual review of the highest-risk categories only
```

If you installed it manually, the command is `/owasp-top10-review`.

Output goes to `.security-review/<date>/` in your project. Add that folder to `.gitignore`. It contains:
- `report.md`
- `attack-surface.md`
- `inventory.md`
- `scanners.md`
- `scanner-findings.md`
- `raw/`

### Optional scanners (macOS)

```bash
brew install semgrep gitleaks osv-scanner hadolint zizmor   # add bandit / gosec / govulncheck for your stack
```

Pin scanner versions. Trivy releases v0.69.4–0.69.6 were compromised in March 2026 (GHSA-69fq-xp46-6x23), and the script refuses to run them.

## Results on the bundled evals

Three intentionally vulnerable apps were reviewed with the skill and without it, using the same model. The apps are an Express full-repo review, a FastAPI API and a PR-diff review. The evals are in [`evals/`](evals/).

| | With skill | Without skill |
|---|---|---|
| Assertions passed | **35 / 36 (97%)** | 24 / 36 (67%) |
| Avg. time per review | ~14 min | ~5 min |

The model without the skill found most of the bugs. Its failures were that it used the OWASP 2021 list, left out the API Top 10 and coverage matrix, and printed a leaked key in the report.
The skill is slower because it builds an attack-surface map, runs scanners and verifies every finding.

## Limitations

This is an assisted code review, not a penetration test or a compliance certification. No tool or review fully covers the OWASP Top 10.
For verification or compliance, use [OWASP ASVS 5.0](https://github.com/OWASP/ASVS).
Only use the skill on code and systems you own or are authorized to test.

## Layout

```
.claude-plugin/marketplace.json
plugins/owasp-security/
  .claude-plugin/plugin.json
  skills/owasp-top10-review/
    SKILL.md                 workflow, ground rules, severity rubric, report rules
    references/              quick checklist, category map + filing rules, per-category deep dives (A01–A10, API1–API10), tooling
    scripts/                 detect_stack.sh, run_scanners.sh, summarize_findings.py, check_headers.sh
    assets/report-template.md
evals/                       intentionally vulnerable fixtures + evals.json + setup script
```

## License and credits

- The skill content in `SKILL.md`, `references/` and `assets/` adapts and summarizes material from the
  [OWASP Top 10:2025](https://owasp.org/Top10/2025/), [OWASP API Security Top 10:2023](https://owasp.org/API-Security/),
  [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) and [OWASP ASVS](https://github.com/OWASP/ASVS).
  All of these are © OWASP Foundation and licensed under **CC BY-SA 4.0**, so this content is released under
  **[CC BY-SA 4.0](LICENSE)** as well. See [ATTRIBUTION.md](ATTRIBUTION.md).
- The scripts in `scripts/` and `evals/setup-fixtures.sh` are released under the **[MIT License](LICENSE-MIT)**.
- This project is not affiliated with or endorsed by the OWASP Foundation or Anthropic.
  OWASP® is a registered trademark of the OWASP Foundation, Inc.

---

## ภาษาไทย

Plugin สำหรับ Claude Code ที่ตรวจ web app และ API ที่คุณพัฒนาเอง ตาม **OWASP Top 10:2025** และ **OWASP API Security Top 10:2023** ผลลัพธ์เป็นรายงานเรียงตามความรุนแรง ทุกข้อระบุ `file:line` และมีโค้ดวิธีแก้

**ติดตั้ง**
```
/plugin marketplace add adisornwplizz/owasp-security-skills
/plugin install owasp-security@owasp-security-skills
```

**ใช้งาน**
- พิมพ์บอกได้เลย เช่น "ตรวจ security ของโปรเจกต์นี้ตาม OWASP ก่อน deploy"
- ตรวจเฉพาะ PR ด้วย `/owasp-security:owasp-top10-review diff main`
- ตรวจแอปที่รันอยู่ในเครื่อง (passive เท่านั้น) ด้วย `--url http://localhost:3000`

**จุดเด่น**
- ใช้ OWASP ฉบับล่าสุด (2025)
- เน้นเรื่องที่ scanner มักตรวจไม่เจอ เช่น IDOR, admin ไม่เช็ก role, mass assignment, business logic และ error ที่ fail-open
- ปิดบัง secret ในรายงาน และไม่ใส่ payload โจมตี
- เขียนรายงานเป็นภาษาเดียวกับที่ผู้ใช้พิมพ์

**ข้อควรทราบ**
- เป็นเครื่องมือช่วย review ไม่ใช่ pentest หรือใบรับรอง compliance
- ใช้กับระบบของตัวเองหรือระบบที่ได้รับอนุญาตเท่านั้น
- เนื้อหาดัดแปลงจากเอกสาร OWASP ซึ่งใช้ CC BY-SA 4.0 ส่วน scripts ใช้ MIT
