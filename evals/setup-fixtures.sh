#!/usr/bin/env bash
# Materialize the eval fixtures into a working directory (default: ./eval-work).
# The fixtures are INTENTIONALLY VULNERABLE demo apps. Never deploy or run them on a public network.
# In this repo their dependency manifests are renamed (*.fixture.*) so GitHub/Dependabot don't treat them as real projects.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/fixtures" && pwd)"
DEST="${1:-./eval-work}"
mkdir -p "$DEST"
DEST="$(cd "$DEST" && pwd)"
commit() { git -c user.email=eval@example.com -c user.name=eval "$@"; }

# 1) shop-api (Express) — full-repo review, Thai prompt
cp -R "$SRC/shop-api" "$DEST/shop-api"
( cd "$DEST/shop-api"
  mv package.fixture.json package.json; mv package-lock.fixture.json package-lock.json; mv env.fixture .env
  git init -q && git add -A && commit commit -qm "shop-api v0.3" )

# 2) notes-api (FastAPI) — API review, English prompt
cp -R "$SRC/notes-api" "$DEST/notes-api"
( cd "$DEST/notes-api"
  mv requirements.fixture.txt requirements.txt
  git init -q && git add -A && commit commit -qm "notes-api beta" )

# 3) billing-svc (Express + Prisma) — PR diff review: main vs feature/invoice-pdf
cp -R "$SRC/billing-svc/base" "$DEST/billing-svc"
( cd "$DEST/billing-svc"
  mv package.fixture.json package.json
  git init -q -b main && git add -A && commit commit -qm "billing-svc 1.4.0"
  git checkout -q -b feature/invoice-pdf
  git apply "$SRC/billing-svc/feature-invoice-pdf.patch"
  git add -A && commit commit -qm "feat: invoice PDF export with custom logo + template" )

echo "Fixtures ready in $DEST"
echo "Open Claude Code in each folder and send the prompt from evals/evals.json."
