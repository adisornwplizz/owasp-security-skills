#!/usr/bin/env bash
# detect_stack.sh — inventory a project for an OWASP review (read-only).
# Usage: detect_stack.sh [project_dir] [out_file]
# Prints a markdown inventory: git state, languages, frameworks, lockfiles,
# API specs, containers/IaC/CI, LLM SDK usage, size. Portable to macOS bash 3.2.
set -u
ROOT="${1:-.}"
OUT_FILE="${2:-}"
cd "$ROOT" 2>/dev/null || { echo "cannot cd to $ROOT" >&2; exit 2; }

EXCL='node_modules|\.git/|vendor/|dist/|build/|\.next/|\.nuxt/|target/|\.venv|venv/|__pycache__|\.security-review|coverage/|\.terraform/|bin/|obj/'

list_files() {
  if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git ls-files --cached --others --exclude-standard 2>/dev/null
  else
    find . -type f 2>/dev/null | sed 's|^\./||'
  fi | grep -Ev "$EXCL"
}

FILES="$(list_files)"
has_file() { printf '%s\n' "$FILES" | grep -Eq "$1"; }
files_matching() { printf '%s\n' "$FILES" | grep -E "$1" | head -n "${2:-20}"; }
count_ext() { printf '%s\n' "$FILES" | grep -Ec "$1"; }
dep_in() { # dep_in <file-regex> <pattern>
  printf '%s\n' "$FILES" | grep -E "$1" | head -n 50 | while IFS= read -r f; do
    grep -Eqi "$2" "$f" 2>/dev/null && { echo yes; break; }
  done
}

emit() {
echo "# Project inventory"
echo
echo "- Path: \`$(pwd)\`"
echo "- Scanned at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "- Git: branch \`$(git rev-parse --abbrev-ref HEAD 2>/dev/null)\`, commit \`$(git rev-parse --short HEAD 2>/dev/null)\`, uncommitted changes: $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
else
  echo "- Git: not a git repository"
fi
echo "- Tracked files (excluding deps/build): $(printf '%s\n' "$FILES" | grep -c .)"

echo; echo "## Languages (file counts)"
for pair in "JavaScript:\.(js|mjs|cjs|jsx)$" "TypeScript:\.(ts|tsx|mts|cts)$" "Python:\.py$" "Java:\.java$" "Kotlin:\.kt$" "Go:\.go$" "PHP:\.php$" "C#:\.cs$" "Ruby:\.rb$" "Rust:\.rs$" "Templates:\.(html|jinja2?|j2|blade\.php|cshtml|razor|vue|svelte|hbs|ejs|pug|erb)$" "SQL:\.sql$"; do
  name="${pair%%:*}"; re="${pair#*:}"; n=$(count_ext "$re")
  [ "$n" -gt 0 ] && echo "- $name: $n"
done

echo; echo "## Frameworks / libraries detected"
fw() { [ "$(dep_in "$1" "$2")" = yes ] && echo "- $3"; }
fw 'package\.json$' '"express"' 'Express (Node)'
fw 'package\.json$' '"@nestjs/core"' 'NestJS (Node)'
fw 'package\.json$' '"next"' 'Next.js'
fw 'package\.json$' '"fastify"' 'Fastify (Node)'
fw 'package\.json$' '"koa"' 'Koa (Node)'
fw 'package\.json$' '"hono"' 'Hono'
fw 'package\.json$' '"(react|react-dom)"' 'React'
fw 'package\.json$' '"vue"' 'Vue'
fw 'package\.json$' '"@angular/core"' 'Angular'
fw 'package\.json$' '"svelte"' 'Svelte'
fw 'package\.json$' '"(apollo-server|@apollo/server|graphql-yoga|graphql)"' 'GraphQL (Node)'
fw 'package\.json$' '"(prisma|@prisma/client)"' 'Prisma ORM'
fw 'package\.json$' '"(mongoose|mongodb)"' 'MongoDB driver/Mongoose'
fw 'package\.json$' '"(sequelize|typeorm|knex|drizzle-orm|pg|mysql2)"' 'SQL client/ORM (Node)'
fw 'package\.json$' '"(jsonwebtoken|jose|passport|next-auth|@auth/core|express-session|lucia|better-auth)"' 'Auth libs (Node)'
fw '(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$' '(^|[^a-z])django([^a-z]|$)' 'Django'
fw '(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$' 'fastapi' 'FastAPI'
fw '(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$' '(^|[^a-z-])flask([^a-z-]|$)' 'Flask'
fw '(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$' 'sqlalchemy' 'SQLAlchemy'
fw '(requirements[^/]*\.txt|pyproject\.toml|Pipfile|setup\.py)$' '(pyjwt|python-jose|authlib)' 'JWT/OAuth libs (Python)'
fw '(pom\.xml|build\.gradle(\.kts)?)$' 'spring-boot' 'Spring Boot'
fw '(pom\.xml|build\.gradle(\.kts)?)$' 'spring-security|spring-boot-starter-security' 'Spring Security'
fw 'go\.mod$' 'gin-gonic/gin' 'Gin (Go)'
fw 'go\.mod$' 'labstack/echo' 'Echo (Go)'
fw 'go\.mod$' 'gofiber/fiber' 'Fiber (Go)'
fw 'go\.mod$' 'go-chi/chi' 'chi (Go)'
fw 'go\.mod$' 'gorm\.io' 'GORM'
fw 'composer\.json$' 'laravel/framework' 'Laravel'
fw 'composer\.json$' 'symfony/' 'Symfony'
fw '\.csproj$' 'Microsoft\.AspNetCore|Sdk="Microsoft\.NET\.Sdk\.Web"' 'ASP.NET Core'
fw 'Gemfile$' 'rails' 'Ruby on Rails'
fw '(package\.json|requirements[^/]*\.txt|pyproject\.toml|go\.mod|pom\.xml|composer\.json|\.csproj)$' '(openai|anthropic|langchain|llamaindex|llama-index|@ai-sdk|"ai"|google-genai|mistral|ollama)' 'LLM SDK present -> also check OWASP LLM Top 10'

echo; echo "## Dependency manifests / lockfiles"
files_matching '(^|/)(package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|package\.json|requirements[^/]*\.txt|poetry\.lock|uv\.lock|Pipfile\.lock|pyproject\.toml|pylock[^/]*\.toml|go\.mod|go\.sum|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|composer\.(json|lock)|[^/]*\.csproj|packages\.lock\.json|Gemfile\.lock|Cargo\.lock)$' 40 | sed 's/^/- /'
has_file '(^|/)package\.json$' && ! has_file '(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$' && echo "- WARNING: package.json without a lockfile (A03 risk)"

echo; echo "## API surface hints"
files_matching '(openapi|swagger)[^/]*\.(ya?ml|json)$' 10 | sed 's/^/- OpenAPI: /'
files_matching '\.(graphql|gql)$' 10 | sed 's/^/- GraphQL schema: /'
files_matching '\.proto$' 10 | sed 's/^/- gRPC proto: /'
files_matching '(^|/)(routes?|controllers?|handlers?|api|endpoints|resolvers|views)(/|\.)' 25 | sed 's/^/- route-ish: /'

echo; echo "## Config, secrets-prone and deployment files"
files_matching '(^|/)\.env([.][^/]*)?$' 20 | sed 's/^/- env file: /'
files_matching '(^|/)(settings|config|application)[^/]*\.(py|ya?ml|json|properties|toml|ts|js)$' 20 | sed 's/^/- config: /'
files_matching '(^|/)(Dockerfile[^/]*|[^/]*\.dockerfile|docker-compose[^/]*\.ya?ml|compose\.ya?ml)$' 20 | sed 's/^/- container: /'
files_matching '\.(tf|bicep)$|(^|/)(k8s|kubernetes|helm|charts)/|cloudformation' 20 | sed 's/^/- IaC: /'
files_matching '(^|/)\.github/workflows/[^/]+\.ya?ml$|(^|/)\.gitlab-ci\.yml$|(^|/)Jenkinsfile$|(^|/)\.circleci/|bitbucket-pipelines\.yml$|azure-pipelines\.yml$' 20 | sed 's/^/- CI: /'

echo; echo "## Tests"
echo "- test files: $(count_ext '(^|/)(tests?|__tests__|spec)/|[._-](test|spec)\.[a-z]+$|_test\.go$')"

echo; echo "## Size"
if command -v wc >/dev/null; then
  loc=$(printf '%s\n' "$FILES" | grep -E '\.(js|mjs|cjs|jsx|ts|tsx|py|java|kt|go|php|cs|rb|rs|vue|svelte)$' | head -n 20000 | tr '\n' '\0' | xargs -0 cat 2>/dev/null | wc -l | tr -d ' ')
  echo "- Approx. source LOC: ${loc:-unknown}"
fi

echo; echo "## Installed scanners"
for t in semgrep opengrep gitleaks trufflehog osv-scanner trivy pip-audit govulncheck bandit gosec hadolint checkov zizmor composer dotnet docker nuclei; do
  if command -v "$t" >/dev/null 2>&1; then echo "- [x] $t"; else echo "- [ ] $t"; fi
done
}

if [ -n "$OUT_FILE" ]; then
  mkdir -p "$(dirname "$OUT_FILE")"
  emit | tee "$OUT_FILE"
else
  emit
fi
