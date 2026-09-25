#!/usr/bin/env bash
# check_headers.sh — passive, non-destructive HTTP checks against YOUR OWN local/staging app.
# Usage: check_headers.sh <base_url> [--path /some/page] [--allow-remote] [--out FILE]
# Sends at most 4 ordinary requests: GET page, GET random 404 path, OPTIONS with a foreign Origin,
# GET with a foreign Origin. No payloads, no auth, no fuzzing.
# Non-local hosts are refused unless --allow-remote (only for staging you own — never production).
set -u
URL=""; P="/"; ALLOW=0; OUTF=""
while [ $# -gt 0 ]; do
  case "$1" in
    --path) P="$2"; shift 2;;
    --allow-remote) ALLOW=1; shift;;
    --out) OUTF="$2"; shift 2;;
    -h|--help) sed -n '2,7p' "$0"; exit 0;;
    *) URL="$1"; shift;;
  esac
done
[ -z "$URL" ] && { echo "usage: $0 <base_url> [--path /x] [--allow-remote]" >&2; exit 2; }
URL="${URL%/}"
HOST=$(printf '%s' "$URL" | sed -E 's#^[a-zA-Z]+://##; s#[/:].*$##')
case "$HOST" in
  localhost|127.*|0.0.0.0|::1|\[::1\]|*.localhost|*.local|*.test|host.docker.internal|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
  *) if [ $ALLOW -ne 1 ]; then
       echo "Refusing non-local host '$HOST'. Re-run with --allow-remote only for a staging app you own (never production)." >&2; exit 3
     fi;;
esac
command -v curl >/dev/null || { echo "curl not found" >&2; exit 2; }

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t owasphdr)
C="curl -sS -k --max-time 15 -o /dev/null -D"
FOREIGN="https://owasp-review.invalid"

emit() {
echo "# HTTP checks for $URL$P  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
$C "$TMP/h1" "$URL$P" || { echo "Request failed — is the app running?"; return; }
H1="$TMP/h1"
status=$(head -n1 "$H1" | tr -d '\r')
echo; echo "Status: \`$status\`"
hv() { grep -i "^$1:" "$H1" | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'; }
is_https=0; case "$URL" in https://*) is_https=1;; esac
ctype=$(hv content-type)
is_html=0; case "$ctype" in *html*) is_html=1;; esac

echo; echo "## Security headers (OWASP HTTP Headers Cheat Sheet / ASVS 5.0 V3.4)"
echo "| Header | Value | Verdict |"; echo "|---|---|---|"
chk() { # name verdict-if-missing  [html-only]
  v=$(hv "$1")
  if [ -z "$v" ]; then
    if [ "${3:-}" = html ] && [ $is_html -eq 0 ]; then echo "| $1 | (absent) | n/a for non-HTML |"; else echo "| $1 | (absent) | $2 |"; fi
  else echo "| $1 | \`$v\` | present — check value |"; fi
}
chk Content-Security-Policy "MISSING (A02; A05 defense-in-depth) — APIs: at least frame-ancestors 'none'"
if [ $is_https -eq 1 ]; then chk Strict-Transport-Security "MISSING (A02/A04) — max-age>=31536000; includeSubDomains"
else echo "| Strict-Transport-Security | - | not testable over http (check prod/staging TLS config) |"; fi
chk X-Content-Type-Options "MISSING (A02) — nosniff"
chk Referrer-Policy "MISSING (A02) — strict-origin-when-cross-origin or no-referrer"
chk Permissions-Policy "missing (Low) — disable unused features" html
chk Cross-Origin-Opener-Policy "missing (Low) — same-origin" html
chk X-Frame-Options "missing (OK if CSP frame-ancestors is set)" html
csp=$(hv Content-Security-Policy)
case "$csp" in *"'unsafe-inline'"*|*"'unsafe-eval'"*) echo "| CSP quality | contains unsafe-inline/unsafe-eval | WEAK (A05 defense-in-depth) |";; esac
xxp=$(hv X-XSS-Protection); case "$xxp" in 1*) echo "| X-XSS-Protection | \`$xxp\` | deprecated — set 0 or remove (Info) |";; esac
cc=$(hv Cache-Control); [ -n "$cc" ] && echo "| Cache-Control | \`$cc\` | sensitive/auth responses need no-store |"

echo; echo "## Information leakage (A02)"
for h in Server X-Powered-By X-AspNet-Version X-AspNetMvc-Version X-Runtime X-Debug-Token X-Debug-Token-Link SourceMap; do
  v=$(hv "$h"); [ -n "$v" ] && echo "- \`$h: $v\` — remove or genericize"
done

echo; echo "## Cookies (A02 / A07; ASVS 5.0 V3.3)"
grep -i '^set-cookie:' "$H1" | tr -d '\r' | while IFS= read -r line; do
  name=$(printf '%s' "$line" | cut -d: -f2- | sed 's/^ *//' | cut -d= -f1)
  issues=""
  printf '%s' "$line" | grep -qi '; *secure' || issues="$issues no-Secure"
  printf '%s' "$line" | grep -qi '; *httponly' || issues="$issues no-HttpOnly(ok only if JS must read it)"
  printf '%s' "$line" | grep -qi '; *samesite=' || issues="$issues no-SameSite"
  printf '%s' "$line" | grep -qi 'samesite=none' && issues="$issues SameSite=None(needs CSRF defense)"
  case "$name" in __Host-*) ;; *) issues="$issues (consider __Host- prefix)";; esac
  echo "- \`$name\`:${issues:- OK}"
done
grep -qi '^set-cookie:' "$H1" || echo "- (no cookies set on this response)"

echo; echo "## Error handling (A10 / A02) — random 404 path"
R="/owasp-review-404-$$-$(date +%s)"
curl -sS -k --max-time 15 -D "$TMP/h2" -o "$TMP/b2" "$URL$R" >/dev/null 2>&1
echo "- \`GET $R\` -> \`$(head -n1 "$TMP/h2" 2>/dev/null | tr -d '\r')\`"
if grep -Eqi 'traceback \(most recent|at [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.(java|kt|cs|js|ts):[0-9]+|node_modules/|/usr/src/app|werkzeug|django\.core|whitelabel error page|stack ?trace|exception in thread|laravel|symfony\\\\component|sqlstate|ORA-[0-9]{5}|\bDEBUG *= *True' "$TMP/b2" 2>/dev/null; then
  echo "- **Verbose error page detected** (stack trace / framework debug output) — A10 CWE-209 or A02 CWE-489 (debug mode)"
else echo "- No stack-trace signatures in the 404 body"; fi

echo; echo "## CORS (A01/A02, CWE-942) — foreign Origin \`$FOREIGN\`"
curl -sS -k --max-time 15 -o /dev/null -D "$TMP/h3" -H "Origin: $FOREIGN" "$URL$P" >/dev/null 2>&1
curl -sS -k --max-time 15 -o /dev/null -D "$TMP/h4" -X OPTIONS -H "Origin: $FOREIGN" -H "Access-Control-Request-Method: GET" "$URL$P" >/dev/null 2>&1
for f in h3 h4; do
  acao=$(grep -i '^access-control-allow-origin:' "$TMP/$f" | head -n1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//')
  acac=$(grep -i '^access-control-allow-credentials:' "$TMP/$f" | head -n1 | cut -d: -f2- | tr -d '\r ' )
  lbl=$([ "$f" = h3 ] && echo GET || echo "OPTIONS preflight")
  if [ -z "$acao" ]; then echo "- $lbl: no ACAO header (foreign origin not allowed) — OK"
  elif [ "$acao" = "$FOREIGN" ] && [ "$acac" = "true" ]; then echo "- $lbl: **reflects arbitrary Origin WITH credentials** — High (A01/A02)"
  elif [ "$acao" = "$FOREIGN" ]; then echo "- $lbl: reflects arbitrary Origin (no credentials) — Medium if responses hold private data"
  elif [ "$acao" = "*" ]; then echo "- $lbl: \`*\` — OK only for public, non-credentialed data"
  else echo "- $lbl: ACAO=\`$acao\` — fixed allowlist, OK"; fi
done
allow=$(grep -i '^allow:\|^access-control-allow-methods:' "$TMP/h4" | head -n1 | cut -d: -f2- | tr -d '\r')
[ -n "$allow" ] && echo "- Allowed methods:$allow (flag TRACE/unused verbs — API8)"
}

if [ -n "$OUTF" ]; then mkdir -p "$(dirname "$OUTF")"; emit | tee "$OUTF"; else emit; fi
rm -rf "$TMP"
