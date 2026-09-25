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

## Sample output

These are real, unedited reports the skill produced on the bundled vulnerable fixtures:
- [FastAPI notes API — English report](examples/report-fastapi-notes-api.en.md), with the [chat summary](examples/chat-reply-fastapi-notes-api.en.md)
- [Express shop API — Thai report](examples/report-express-shop-api.th.md)

## Quick start

1. In a Claude Code session, add the marketplace and install the plugin:
   ```
   /plugin marketplace add adisornwplizz/owasp-security-skills
   /plugin install owasp-security@owasp-security-skills
   ```
   The install command opens the plugin's details. Choose **Install for you (user scope)** to use it in every project on this machine.
2. Open Claude Code in the project you want to check.
3. Type: `Check the security of this project against OWASP Top 10`

## Install

| Where | Commands |
|---|---|
| Claude Code session | `/plugin marketplace add adisornwplizz/owasp-security-skills` then `/plugin install owasp-security@owasp-security-skills` |
| One step (Claude Code v2.1.275+) | `/plugin install owasp-security --marketplace adisornwplizz/owasp-security-skills` |
| Your shell (scripts, dotfiles) | `claude plugin marketplace add adisornwplizz/owasp-security-skills && claude plugin install owasp-security@owasp-security-skills` |
| Desktop app / VS Code | A user-scope install from the terminal also appears in the desktop app's local sessions and in VS Code. In VS Code you can instead type `/plugins`, add `adisornwplizz/owasp-security-skills` on the **Marketplaces** tab, then install **owasp-security** |

Check that it is installed. Type `/` in a session and look for `/owasp-security:owasp-top10-review`, or run
`claude plugin list` in your shell.

To install it manually as a plain user-level skill, without the plugin system:

```bash
git clone https://github.com/adisornwplizz/owasp-security-skills.git
mkdir -p ~/.claude/skills
cp -R owasp-security-skills/plugins/owasp-security/skills/owasp-top10-review ~/.claude/skills/
```

A manual install is invoked as `/owasp-top10-review` and does not update itself.

## Usage guide

### 1. Start a review

Just ask in plain language. Claude picks the skill automatically.

| You say | What it does |
|---|---|
| "Check the security of this project before I deploy" | Full-repo review |
| "ตรวจ security ตาม OWASP ให้หน่อย" | Same, with the report in Thai |
| "Review the security of branch feature/x against main" | Reviews only the diff, plus related context such as middleware order |
| "Security review, the app is running on http://localhost:3000" | Full review plus passive runtime checks |

You can also call it directly with options:

```
/owasp-security:owasp-top10-review                          # full repo (default)
/owasp-security:owasp-top10-review diff main                # only changes vs main (PR review)
/owasp-security:owasp-top10-review src/api                  # one folder
/owasp-security:owasp-top10-review --url http://localhost:3000   # + passive header/cookie/CORS/error-page checks
/owasp-security:owasp-top10-review --quick                  # faster: skip scanners, focus on A01, A07, A05, A02 and API1–API5
```

### 2. What happens during a run

1. **Inventory:** it detects your languages, frameworks, lockfiles, Dockerfiles and CI, then maps the attack surface: routes, authentication, authorization, data access and outbound calls.
2. **Scanners:** it runs the scanners you have installed. Claude Code may ask you to approve the command. Semgrep downloads its rules, and the audit tools and OSV send package names and versions to their advisory APIs. Your source code is never uploaded.
3. **Manual review:** it goes through every OWASP category, with extra depth where scanners are weak: authorization, business logic, error handling and logging.
4. **Report:** it writes `.security-review/<date>/report.md` and replies in chat with a verdict, counts by severity and the top 3 fixes.

A small app takes about 10–15 minutes. Your source code is never changed unless you ask for fixes afterwards.

### 3. Read the report

`report.md` has these sections, in order:
- **Executive summary:** overall risk, a go/no-go verdict, and what to fix first.
- **Coverage matrix:** every Top 10:2025 category, plus API Top 10:2023 categories for APIs, marked ❌ issue, ⚠️ needs manual check, ✅ nothing found in scope, or N/A.
- **Findings:**
  - Critical and High get a full write-up: `file:line`, evidence, impact, a code fix for your framework, and how to verify the fix.
  - Medium, Low and Info are listed in a table.
- **Remediation plan:** what to fix now, next sprint, and backlog.
- **Scope and limitations:** which tools ran and what was not covered.

Other files in `.security-review/<date>/`:
- `attack-surface.md`
- `inventory.md`
- `scanners.md`
- `scanner-findings.md` (unverified scanner leads)
- `raw/`

Add `.security-review/` to your `.gitignore`.

### 4. After the report

- Ask Claude to fix the findings, for example "fix the Critical and High findings". Review each change.
- Run the review again after fixing, or use `diff main` on your fix branch.
- Ask it to add the scanners to CI or a pre-commit hook so the same issues don't come back.

### Optional scanners (recommended)

The skill works without any scanners, but scanners add dependency CVE and secret detection.

```bash
# macOS
brew install semgrep gitleaks osv-scanner hadolint zizmor
# add for your stack: bandit (Python), gosec + govulncheck (Go)
```

Pin scanner versions. Trivy releases v0.69.4–0.69.6 were compromised in March 2026 (GHSA-69fq-xp46-6x23), and the script refuses to run them.

### Update and uninstall

Auto-update is off by default for third-party marketplaces.

| Action | Inside a session | In your shell |
|---|---|---|
| Refresh the marketplace | `/plugin marketplace update owasp-security-skills` | `claude plugin marketplace update owasp-security-skills` |
| Update the plugin | `/plugin` → Installed → owasp-security → **Update now** | `claude plugin update owasp-security@owasp-security-skills` |
| Turn on auto-update | `/plugin` → Marketplaces → owasp-security-skills → **Enable auto-update** | — |
| Uninstall | `/plugin uninstall` | `claude plugin uninstall owasp-security@owasp-security-skills` |

### Troubleshooting

- **The skill doesn't start when you ask:** call it directly with `/owasp-security:owasp-top10-review`. Check `claude plugin list` shows it enabled, then run `/reload-plugins`.
- **"semgrep failed" or other scanner errors:** usually a network block on rule downloads. The review continues with the other tools and manual review, and the report lists what didn't run.
- **Runtime checks refuse a URL:** only local hosts are allowed by default. Use a staging URL only if you own it; the skill will ask before using `--allow-remote`. Never point it at production.
- **Cloud sessions (claude.ai/code):** they don't load plugins installed on your machine. Use a local session, or the manual install in the repo.

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
examples/                    sample reports produced by the skill
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

### เริ่มใช้งานใน 3 ขั้นตอน
1. ติดตั้งจากใน Claude Code:
   ```
   /plugin marketplace add adisornwplizz/owasp-security-skills
   /plugin install owasp-security@owasp-security-skills
   ```
   เลือก **Install for you (user scope)** เพื่อให้ใช้ได้ทุกโปรเจกต์ในเครื่อง
2. เปิด Claude Code ในโปรเจกต์ที่ต้องการตรวจ
3. พิมพ์ว่า "ตรวจ security ของโปรเจกต์นี้ตาม OWASP"

### วิธีสั่งงาน
| พิมพ์ว่า | ผลลัพธ์ |
|---|---|
| "ตรวจ security ก่อน deploy" | ตรวจทั้ง repo |
| "review security ของ branch feature/x เทียบกับ main" | ตรวจเฉพาะส่วนที่เปลี่ยนใน PR |
| "ตรวจ security แอปรันอยู่ที่ http://localhost:3000" | ตรวจโค้ด และเช็คแอปที่รันอยู่แบบ passive (header, cookie, CORS, หน้า error) |
| `/owasp-security:owasp-top10-review --quick` | ตรวจแบบเร็ว ข้าม scanner และเน้นหมวดเสี่ยงสูง |

### ระหว่างตรวจ
1. สำรวจ stack และ attack surface
2. รัน scanner ที่ติดตั้งไว้ ระบบอาจขอให้กดอนุญาตก่อน
3. review ทีละหมวด
4. เขียนรายงาน

แอปเล็กใช้เวลาประมาณ 10–15 นาที และจะไม่แก้โค้ดจนกว่าคุณสั่ง

### อ่านผล
รายงานอยู่ที่ `.security-review/<วันที่>/report.md` มีส่วนต่างๆ ตามลำดับ:
- **สรุป:** ระดับความเสี่ยง, go/no-go, และอะไรที่ต้องแก้ก่อน
- **ตาราง coverage:** ครบทุกหมวด
- **รายละเอียด findings:**
  - Critical และ High เขียนเต็ม: ตำแหน่ง, หลักฐาน, ผลกระทบ, โค้ดแก้ และวิธีตรวจว่าแก้แล้ว
  - Medium และ Low สรุปเป็นตาราง
- **แผนการแก้**

ให้เพิ่ม `.security-review/` ลงใน `.gitignore` ด้วย

### หลังได้รายงาน
- สั่งต่อได้เลย เช่น "แก้ Critical กับ High ให้หน่อย"
- แก้เสร็จแล้วรันตรวจซ้ำ หรือใช้ `diff main` กับ branch ที่แก้
- ขอให้ช่วยเพิ่ม scanner เข้า CI

### อัปเดต / ถอนการติดตั้ง
- marketplace ภายนอกปิด auto-update ไว้เป็นค่าเริ่มต้น
- อัปเดตด้วย `/plugin marketplace update owasp-security-skills` แล้วเข้า `/plugin` → Installed → **Update now**
- ถอนการติดตั้งด้วย `/plugin uninstall`

**ตัวอย่างผลลัพธ์:** [รายงานภาษาไทย](examples/report-express-shop-api.th.md) · [รายงานภาษาอังกฤษ](examples/report-fastapi-notes-api.en.md)

**ข้อควรทราบ**
- เป็นเครื่องมือช่วย review ไม่ใช่ pentest หรือใบรับรอง compliance
- ใช้กับระบบของตัวเองหรือระบบที่ได้รับอนุญาตเท่านั้น
- เนื้อหาดัดแปลงจากเอกสาร OWASP ซึ่งใช้ CC BY-SA 4.0 ส่วน scripts ใช้ MIT
