#!/usr/bin/env python3
"""summarize_findings.py — normalize scanner output into OWASP Top 10:2025 buckets.

Usage: python3 summarize_findings.py <review_dir>      (reads <review_dir>/raw/*)
Writes: <review_dir>/scanner-findings.md and <review_dir>/scanner-findings.json

Scanner hits are LEADS, not findings: each one must be confirmed by reading the code.
Category = explicit 2025 tag from the rule if present, else CWE -> 2025 map (official
lists from github.com/OWASP/Top10 2025/docs/en), else a per-tool default.
Standard library only (Python 3.8+).
"""
import json, os, re, sys, glob
from collections import defaultdict

CWE_2025 = {
 "A01": [22,23,36,59,61,65,200,201,219,276,281,282,283,284,285,352,359,377,379,402,424,425,441,497,538,540,548,552,566,601,615,639,668,732,749,862,863,918,922,1275],
 "A02": [5,11,13,15,16,260,315,489,526,547,611,614,776,942,1004,1174],
 "A03": [447,477,1035,1104,1329,1357,1395],
 "A04": [261,296,319,320,321,322,323,324,325,326,327,328,329,330,331,332,334,335,336,337,338,340,342,347,523,757,759,760,780,916,1240,1241],
 "A05": [20,74,76,77,78,79,80,83,86,88,89,90,91,93,94,95,96,97,98,99,103,104,112,113,114,115,116,129,159,470,493,500,564,610,643,644,917],
 "A06": [73,183,256,266,269,286,311,312,313,316,362,382,419,434,436,444,451,454,472,501,522,525,539,598,602,628,642,646,653,656,657,676,693,799,807,841,1021,1022,1125],
 "A07": [258,259,287,288,289,290,291,293,294,295,297,298,299,300,302,303,304,305,306,307,308,309,346,350,384,521,613,620,640,798,940,941,1390,1391,1392,1393],
 "A08": [345,353,426,427,494,502,506,509,565,784,829,830,915,926],
 "A09": [117,221,223,532,778],
 "A10": [209,215,234,235,248,252,274,280,369,390,391,394,396,397,460,476,478,484,550,636,703,754,755,756],
}
NAMES = {
 "A01": "Broken Access Control", "A02": "Security Misconfiguration", "A03": "Software Supply Chain Failures",
 "A04": "Cryptographic Failures", "A05": "Injection", "A06": "Insecure Design", "A07": "Authentication Failures",
 "A08": "Software or Data Integrity Failures", "A09": "Security Logging & Alerting Failures",
 "A10": "Mishandling of Exceptional Conditions", "UNMAPPED": "Unmapped (triage manually)",
}
CWE_TO_CAT = {c: cat for cat, cwes in CWE_2025.items() for c in cwes}
# closest-fit for common CWEs that are not in any 2025 list
CWE_TO_CAT.update({400: "A06", 770: "A06", 1333: "A06", 601: "A01", 1321: "A08", 250: "A02"})

TOOL_DEFAULT = {  # (category, cwe) when a rule carries no CWE / 2025 tag
 "gitleaks": ("A07", 798), "trufflehog": ("A07", 798),
 "osv-scanner": ("A03", 1395), "osv": ("A03", 1395), "govulncheck": ("A03", 1395),
 "npm-audit": ("A03", 1395), "pnpm-audit": ("A03", 1395), "yarn-audit": ("A03", 1395),
 "composer-audit": ("A03", 1395), "dotnet-vuln": ("A03", 1395),
 "hadolint": ("A02", 16), "checkov": ("A02", 16), "zizmor": ("A03", 1357),
}
LEVEL_SEV = {"error": "High", "warning": "Medium", "note": "Low", "none": "Info"}
ORDER = ["Critical", "High", "Medium", "Low", "Info"]

def cvss_band(x):
    try: x = float(x)
    except (TypeError, ValueError): return None
    if x >= 9: return "Critical"
    if x >= 7: return "High"
    if x >= 4: return "Medium"
    if x > 0: return "Low"
    return "Info"

def norm_sev(s):
    s = (s or "").lower()
    return {"critical": "Critical", "high": "High", "moderate": "Medium", "medium": "Medium",
            "low": "Low", "info": "Info", "informational": "Info", "error": "High",
            "warning": "Medium", "note": "Low"}.get(s, "Medium")

def cwes_from(texts):
    out = []
    for t in texts:
        for m in re.finditer(r"cwe[-_/ :]?0*(\d{1,4})", str(t), re.I):
            out.append(int(m.group(1)))
    return list(dict.fromkeys(out))

def cat_from(texts, cwes, tool):
    for t in texts:
        m = re.search(r"\bA(0[1-9]|10):2025\b", str(t))
        if m: return "A" + m.group(1)
    for c in cwes:
        if c in CWE_TO_CAT: return CWE_TO_CAT[c]
    return TOOL_DEFAULT.get(tool, ("UNMAPPED", None))[0]

def add(findings, tool, rule, sev, path, line, msg, cwes, texts):
    if not cwes and tool in TOOL_DEFAULT and TOOL_DEFAULT[tool][1]:
        cwes = [TOOL_DEFAULT[tool][1]]
    findings.append({
        "tool": tool, "rule": rule, "severity": sev, "category": cat_from(texts, cwes, tool),
        "cwe": cwes[:3], "file": path or "", "line": line or "",
        "message": re.sub(r"\s+", " ", (msg or ""))[:220],
    })

def tool_name(fname):
    base = os.path.basename(fname).split(".")[0]
    for k in ["gitleaks", "semgrep", "osv", "trivy", "bandit", "gosec", "hadolint", "zizmor",
              "checkov", "govulncheck", "npm-audit", "pnpm-audit", "yarn-audit", "composer-audit", "dotnet-vuln"]:
        if base.startswith(k): return "osv-scanner" if k == "osv" else k
    return base

def parse_sarif(path, findings):
    tool = tool_name(path)
    try: data = json.load(open(path, encoding="utf-8"))
    except Exception as e:
        print(f"skip {path}: {e}", file=sys.stderr); return
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rules = {}
        for r in driver.get("rules", []) or []:
            rules[r.get("id")] = r
        for ext in run.get("tool", {}).get("extensions", []) or []:
            for r in ext.get("rules", []) or []:
                rules.setdefault(r.get("id"), r)
        for res in run.get("results", []) or []:
            rid = res.get("ruleId") or (res.get("rule") or {}).get("id") or "?"
            r = rules.get(rid, {})
            props = r.get("properties", {}) or {}
            texts = list(props.get("tags", []) or []) + [props.get("cwe", ""), rid,
                     (r.get("shortDescription") or {}).get("text", "")]
            cwes = cwes_from(texts)
            sev = cvss_band(props.get("security-severity")) or \
                  LEVEL_SEV.get(res.get("level") or (r.get("defaultConfiguration") or {}).get("level", "warning"), "Medium")
            if tool in ("gitleaks", "trufflehog"): sev = "High"
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = (loc.get("region") or {}).get("startLine", "")
            msg = (res.get("message") or {}).get("text", "") or (r.get("shortDescription") or {}).get("text", "")
            add(findings, tool, rid, sev, uri, line, msg, cwes, texts)

def parse_bandit(path, findings):
    data = json.load(open(path, encoding="utf-8"))
    for r in data.get("results", []):
        cwe = (r.get("issue_cwe") or {}).get("id")
        add(findings, "bandit", r.get("test_id"), norm_sev(r.get("issue_severity")),
            r.get("filename"), r.get("line_number"), r.get("issue_text"), [cwe] if cwe else [], [])

def parse_npm(path, findings, tool):
    try: data = json.load(open(path, encoding="utf-8"))
    except Exception:
        return
    for name, v in (data.get("vulnerabilities") or {}).items():  # npm v7+
        vias = [x for x in v.get("via", []) if isinstance(x, dict)]
        if not vias: continue  # transitive-only entry; the root advisory is listed elsewhere
        for via in vias:
            cw = cwes_from(via.get("cwe", []) or [])
            add(findings, tool, via.get("url", "advisory"), norm_sev(via.get("severity")),
                "package-lock.json", "", f"{name} {via.get('range','')}: {via.get('title','')}", cw, [])
    for adv in (data.get("advisories") or {}).values():  # pnpm / npm v6
        cw = cwes_from(adv.get("cwe", []) if isinstance(adv.get("cwe"), list) else [adv.get("cwe", "")])
        add(findings, tool, adv.get("url", "advisory"), norm_sev(adv.get("severity")),
            "lockfile", "", f"{adv.get('module_name')} {adv.get('vulnerable_versions','')}: {adv.get('title','')}", cw, [])

def parse_composer(path, findings):
    data = json.load(open(path, encoding="utf-8"))
    for pkg, advs in (data.get("advisories") or {}).items():
        for a in (advs.values() if isinstance(advs, dict) else advs):
            add(findings, "composer-audit", a.get("cve") or a.get("advisoryId"), norm_sev(a.get("severity") or "high"),
                "composer.lock", "", f"{pkg} {a.get('affectedVersions','')}: {a.get('title','')}", [], [])

def parse_dotnet(path, findings):
    data = json.load(open(path, encoding="utf-8"))
    for p in data.get("projects", []):
        for fw in p.get("frameworks", []):
            for key in ("topLevelPackages", "transitivePackages"):
                for pkg in fw.get(key, []) or []:
                    for v in pkg.get("vulnerabilities", []) or []:
                        add(findings, "dotnet-vuln", v.get("advisoryurl"), norm_sev(v.get("severity")),
                            os.path.basename(p.get("path", "")), "", f"{pkg.get('id')} {pkg.get('resolvedVersion','')}", [], [])

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    rd = sys.argv[1]; raw = os.path.join(rd, "raw")
    findings = []
    for f in sorted(glob.glob(os.path.join(raw, "*.sarif"))):
        parse_sarif(f, findings)
    handlers = {"bandit.json": parse_bandit, "composer-audit.json": parse_composer, "dotnet-vuln.json": parse_dotnet}
    for fname, fn in handlers.items():
        p = os.path.join(raw, fname)
        if os.path.exists(p) and os.path.getsize(p) > 0:
            try: fn(p, findings)
            except Exception as e: print(f"skip {p}: {e}", file=sys.stderr)
    for t in ("npm-audit", "pnpm-audit"):
        p = os.path.join(raw, t + ".json")
        if os.path.exists(p) and os.path.getsize(p) > 0: parse_npm(p, findings, t)

    # de-duplicate identical tool/rule/file/line
    seen, uniq = set(), []
    for f in findings:
        k = (f["tool"], f["rule"], f["file"], f["line"], f["message"][:60])
        if k not in seen: seen.add(k); uniq.append(f)
    findings = uniq

    by_cat = defaultdict(list)
    for f in findings: by_cat[f["category"]].append(f)
    json.dump(findings, open(os.path.join(rd, "scanner-findings.json"), "w"), indent=1)

    lines = ["# Scanner leads (unverified)", "",
             "Every row is a lead to confirm by reading the code — not a finding yet.", "",
             "| Category | Leads | Critical | High | Medium | Low | Info |", "|---|---|---|---|---|---|---|"]
    cats = [c for c in list(NAMES) if c in by_cat]
    for c in cats:
        cnt = {s: sum(1 for f in by_cat[c] if f["severity"] == s) for s in ORDER}
        lines.append(f"| {c} {NAMES[c]} | {len(by_cat[c])} | " + " | ".join(str(cnt[s]) for s in ORDER) + " |")
    if not findings: lines.append("| (none) | 0 | 0 | 0 | 0 | 0 | 0 |")
    for c in cats:
        items = sorted(by_cat[c], key=lambda f: (ORDER.index(f["severity"]), f["file"], str(f["line"])))
        lines += ["", f"## {c} — {NAMES[c]} ({len(items)})", "", "| Sev | Tool | Rule | Location | CWE | Message |", "|---|---|---|---|---|---|"]
        for f in items[:60]:
            loc = f"{f['file']}:{f['line']}" if f["line"] != "" else f["file"]
            cw = ",".join(f"CWE-{c}" for c in f["cwe"])
            msg = f["message"].replace("|", "\\|")
            rule = str(f["rule"]).replace("|", "\\|")[:70]
            lines.append(f"| {f['severity']} | {f['tool']} | {rule} | {loc} | {cw} | {msg} |")
        if len(items) > 60: lines.append(f"| … | | | {len(items)-60} more in scanner-findings.json | | |")
    open(os.path.join(rd, "scanner-findings.md"), "w").write("\n".join(lines) + "\n")
    print("\n".join(lines[:6 + len(cats) + 1]))
    print(f"\nWrote {os.path.join(rd, 'scanner-findings.md')} ({len(findings)} leads)")

if __name__ == "__main__":
    main()
