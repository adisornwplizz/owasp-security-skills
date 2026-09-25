#!/usr/bin/env bash
# run_scanners.sh — run whichever free security scanners are installed (never installs anything).
# Usage: run_scanners.sh [project_dir] [--out DIR] [--offline] [--skip tool1,tool2]
#
# Network: Semgrep downloads registry rules (metrics off); osv-scanner / npm|pnpm|yarn audit /
# govulncheck / composer / dotnet send package names+versions to advisory APIs; trivy downloads its DB.
# Source code is never uploaded. --offline skips every networked tool.
# Secrets are redacted (gitleaks --redact, trufflehog not run with verification).
set -u
ROOT="."; OUT=""; OFFLINE=0; SKIP=""
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2;;
    --offline) OFFLINE=1; shift;;
    --skip) SKIP=",$2,"; shift 2;;
    -h|--help) sed -n '2,9p' "$0"; exit 0;;
    *) ROOT="$1"; shift;;
  esac
done
cd "$ROOT" || { echo "cannot cd to $ROOT" >&2; exit 2; }
[ -z "$OUT" ] && OUT=".security-review/$(date +%Y-%m-%d)"
RAW="$OUT/raw"; mkdir -p "$RAW"
LOG="$OUT/scanners.md"
: > "$LOG"
echo "# Scanner run — $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$LOG"
echo "" >> "$LOG"
echo "| Tool | Version | Status | Output |" >> "$LOG"
echo "|---|---|---|---|" >> "$LOG"

EXCL_FIND='-not -path */node_modules/* -not -path */.git/* -not -path */vendor/* -not -path */.venv/* -not -path */venv/* -not -path */dist/* -not -path */build/* -not -path */.security-review/*'
exists() { find . -maxdepth 4 $EXCL_FIND -name "$1" -print -quit 2>/dev/null | grep -q .; }
skipped() { case "$SKIP" in *",$1,"*) return 0;; esac; return 1; }
row() { echo "| $1 | $2 | $3 | $4 |" >> "$LOG"; }
ver() { "$@" 2>/dev/null | head -n 1 | tr -d '|' | cut -c1-40; }
missing() { row "$1" "-" "not installed — $2" "-"; }

run() { # run <name> <version> <outfile> <cmd...>   (exit codes 0/1 both mean 'ran')
  name="$1"; v="$2"; outf="$3"; shift 3
  echo ">> $name" >&2
  "$@" >"$RAW/$name.stdout.log" 2>"$RAW/$name.stderr.log"; rc=$?
  if [ -s "$outf" ] || [ $rc -le 1 ]; then row "$name" "$v" "ran (exit $rc)" "\`${outf#$OUT/}\`"
  else
    last=$(grep -v '^[[:space:]]*$' "$RAW/$name.stderr.log" 2>/dev/null | tail -n 1 | tr -d '|' | cut -c1-120)
    row "$name" "$v" "FAILED (exit $rc): ${last:-see raw/$name.stderr.log}" "-"
  fi
}

# ---------- Secrets (offline) ----------
if ! skipped gitleaks; then
  if command -v gitleaks >/dev/null; then
    V=$(ver gitleaks version)
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      run gitleaks-history "$V" "$RAW/gitleaks-history.sarif" gitleaks git --redact --no-banner -f sarif -r "$RAW/gitleaks-history.sarif" .
    fi
    run gitleaks-tree "$V" "$RAW/gitleaks-tree.sarif" gitleaks dir --redact --no-banner -f sarif -r "$RAW/gitleaks-tree.sarif" .
  else missing gitleaks "brew install gitleaks"; fi
fi

# ---------- SAST ----------
if ! skipped semgrep; then
  if [ $OFFLINE -eq 1 ]; then row semgrep "-" "skipped (--offline; registry rules need network)" "-"
  elif command -v semgrep >/dev/null; then
    V=$(ver semgrep --version)
    CFG="--config p/default --config p/owasp-top-ten --config p/secrets"
    exists package.json && CFG="$CFG --config p/javascript --config p/typescript --config p/nodejs"
    { exists '*.jsx' || exists '*.tsx'; } && CFG="$CFG --config p/react"
    exists '*.py' && CFG="$CFG --config p/python"
    exists manage.py && CFG="$CFG --config p/django"
    { exists pom.xml || exists 'build.gradle*'; } && CFG="$CFG --config p/java"
    exists go.mod && CFG="$CFG --config p/golang"
    exists composer.json && CFG="$CFG --config p/php"
    exists '*.csproj' && CFG="$CFG --config p/csharp"
    exists 'Dockerfile*' && CFG="$CFG --config p/dockerfile"
    [ -d .github/workflows ] && CFG="$CFG --config p/github-actions"
    # shellcheck disable=SC2086
    run semgrep "$V" "$RAW/semgrep.sarif" semgrep scan --metrics=off --quiet $CFG --sarif-output="$RAW/semgrep.sarif" --json-output="$RAW/semgrep.json" .
  else missing semgrep "brew install semgrep (or pipx install semgrep)"; fi
fi

if ! skipped bandit && exists '*.py'; then
  if command -v bandit >/dev/null; then
    run bandit "$(ver bandit --version)" "$RAW/bandit.json" bandit -r . -q -x ./.venv,./venv,./node_modules,./tests,./test -f json -o "$RAW/bandit.json"
  else missing bandit "brew install bandit"; fi
fi

if ! skipped gosec && exists go.mod; then
  if command -v gosec >/dev/null; then
    run gosec "$(ver gosec -version)" "$RAW/gosec.sarif" gosec -quiet -no-fail -exclude-generated -fmt=sarif -out="$RAW/gosec.sarif" ./...
  else missing gosec "brew install gosec"; fi
fi

# ---------- SCA (A03) ----------
if ! skipped osv-scanner; then
  if [ $OFFLINE -eq 1 ]; then row osv-scanner "-" "skipped (--offline)" "-"
  elif command -v osv-scanner >/dev/null; then
    run osv-scanner "$(ver osv-scanner --version)" "$RAW/osv.sarif" osv-scanner scan source -r --format sarif --output-file "$RAW/osv.sarif" .
  else missing osv-scanner "brew install osv-scanner"; fi
fi

if ! skipped trivy; then
  if [ $OFFLINE -eq 1 ]; then row trivy "-" "skipped (--offline; downloads DB)" "-"
  elif command -v trivy >/dev/null; then
    TV=$(trivy --version 2>/dev/null | head -n1 | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
    case "$TV" in
      0.69.4|0.69.5|0.69.6) row trivy "$TV" "NOT RUN — compromised release (GHSA-69fq-xp46-6x23); reinstall a verified version" "-";;
      *) run trivy "$TV" "$RAW/trivy.sarif" trivy fs --quiet --scanners vuln,misconfig --format sarif -o "$RAW/trivy.sarif" .;;
    esac
  else missing trivy "brew install trivy (optional if osv-scanner is present)"; fi
fi

if ! skipped npm-audit && [ $OFFLINE -eq 0 ]; then
  if [ -f package-lock.json ] && command -v npm >/dev/null; then
    run npm-audit "$(ver npm --version)" "$RAW/npm-audit.json" sh -c "npm audit --json --omit=dev > '$RAW/npm-audit.json'"
  elif [ -f pnpm-lock.yaml ] && command -v pnpm >/dev/null; then
    run pnpm-audit "$(ver pnpm --version)" "$RAW/pnpm-audit.json" sh -c "pnpm audit --json --prod > '$RAW/pnpm-audit.json'"
  elif [ -f yarn.lock ] && command -v yarn >/dev/null; then
    run yarn-audit "$(ver yarn --version)" "$RAW/yarn-audit.json" sh -c "(yarn npm audit --all --recursive --json 2>/dev/null || yarn audit --json) > '$RAW/yarn-audit.json'"
  fi
fi

if ! skipped govulncheck && exists go.mod && [ $OFFLINE -eq 0 ]; then
  if command -v govulncheck >/dev/null; then
    run govulncheck "$(ver govulncheck -version)" "$RAW/govulncheck.sarif" sh -c "govulncheck -format sarif ./... > '$RAW/govulncheck.sarif'"
  else missing govulncheck "brew install govulncheck"; fi
fi

if ! skipped composer && [ -f composer.lock ] && [ $OFFLINE -eq 0 ]; then
  if command -v composer >/dev/null; then
    run composer-audit "$(ver composer --version)" "$RAW/composer-audit.json" sh -c "composer audit --locked --format=json > '$RAW/composer-audit.json'"
  else missing composer "brew install composer"; fi
fi

if ! skipped dotnet && exists '*.csproj' && [ $OFFLINE -eq 0 ]; then
  if command -v dotnet >/dev/null; then
    run dotnet-vuln "$(ver dotnet --version)" "$RAW/dotnet-vuln.json" sh -c "(dotnet package list --vulnerable --include-transitive --format json 2>/dev/null || dotnet list package --vulnerable --include-transitive --format json) > '$RAW/dotnet-vuln.json'"
  fi
fi

# ---------- Config / container / CI (offline) ----------
if ! skipped hadolint && exists 'Dockerfile*'; then
  if command -v hadolint >/dev/null; then
    DF=$(find . -maxdepth 4 $EXCL_FIND -name 'Dockerfile*' 2>/dev/null | head -n 10)
    # shellcheck disable=SC2086
    run hadolint "$(ver hadolint --version)" "$RAW/hadolint.sarif" sh -c "hadolint -f sarif $DF > '$RAW/hadolint.sarif'"
  else missing hadolint "brew install hadolint"; fi
fi

if ! skipped zizmor && [ -d .github/workflows ]; then
  if command -v zizmor >/dev/null; then
    run zizmor "$(ver zizmor --version)" "$RAW/zizmor.sarif" sh -c "zizmor --offline --format=sarif .github/workflows/ > '$RAW/zizmor.sarif'"
  else missing zizmor "brew install zizmor"; fi
fi

if ! skipped checkov && { exists '*.tf' || [ -d k8s ] || [ -d helm ] || [ -d charts ]; }; then
  if command -v checkov >/dev/null; then
    run checkov "$(ver checkov --version)" "$RAW/checkov.sarif" sh -c "checkov -d . --quiet --compact --skip-download -o sarif --output-file-path '$RAW' >/dev/null; [ -f '$RAW/results_sarif.sarif' ] && mv '$RAW/results_sarif.sarif' '$RAW/checkov.sarif'"
  else missing checkov "brew install checkov"; fi
fi

{
  echo ""
  echo "Scanners cover only part of the OWASP Top 10 (authorization, business logic, logging/alerting,"
  echo "exception handling and API inventory need manual review). OWASP discourages claims of full tool coverage."
} >> "$LOG"
cat "$LOG"
echo "" ; echo "Raw outputs: $RAW"
