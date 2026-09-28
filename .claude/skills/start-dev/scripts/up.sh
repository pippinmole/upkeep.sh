#!/usr/bin/env bash
# Starts the local dev stack: postgres + migrate + api in Docker, then the
# Next.js dev server natively on the host (NOT in Docker — see the "why not
# web in Docker" note in ../SKILL.md; short version: Turbopack's dev
# filesystem cache and file watcher were found to serve stale builds under
# a Docker bind mount, so `web` was deliberately removed from
# docker-compose.dev.yml).
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "==> Starting postgres, migrate, api, worker via docker compose (rebuilding images from current source)..."
docker compose -f docker-compose.dev.yml up -d --build

echo "==> Waiting for postgres to report healthy..."
for i in $(seq 1 30); do
  status="$(docker inspect --format '{{.State.Health.Status}}' security-whatnot-dev-postgres-1 2>/dev/null || echo "starting")"
  if [ "$status" = "healthy" ]; then
    break
  fi
  sleep 1
done

echo "==> Waiting for the API to answer on :8080..."
for i in $(seq 1 30); do
  if curl -s -o /dev/null http://localhost:8080/ 2>/dev/null; then
    break
  fi
  sleep 1
done

cd "$REPO_ROOT/web"

if [ ! -f .env.local ]; then
  echo "==> web/.env.local missing, creating it from .env.example..."
  cp .env.example .env.local
  # Generate a real secret instead of leaving the placeholder in place —
  # Auth.js needs an actual random value to sign session JWTs, and the
  # placeholder in .env.example is intentionally not a usable secret.
  SECRET="$(openssl rand -base64 32)"
  # Portable in-place edit: BSD sed (macOS) and GNU sed (Linux/Git Bash)
  # disagree on `-i` syntax, so write to a temp file instead of relying on it.
  awk -v secret="$SECRET" '{gsub(/^AUTH_SECRET=.*/, "AUTH_SECRET=" secret); print}' .env.local > .env.local.tmp
  mv .env.local.tmp .env.local
  echo "    Generated a fresh AUTH_SECRET."
fi

# Report emails: the dev worker (docker-compose.dev.yml) renders them through
# this dev server with a fixed dev-only secret. A .env.local made before
# reports existed lacks the pair, so add the values from .env.example.
if ! grep -q '^SW_INTERNAL_RENDER_SECRET=' .env.local; then
  echo "==> Adding the report render settings (SW_INTERNAL_RENDER_SECRET, SW_WEB_INTERNAL_URL) to web/.env.local..."
  {
    echo ""
    grep -E '^SW_(INTERNAL_RENDER_SECRET|WEB_INTERNAL_URL)=' .env.example
  } >> .env.local
fi

echo "==> Installing web dependencies (bun install, only reinstalls if the lockfile changed)..."
bun install

echo "==> Starting the Next.js dev server (Turbopack, native — not Docker)..."
echo "    web/next.config.ts already disables experimental.turbopackFileSystemCacheForDev;"
echo "    don't re-enable that without confirming hot reload still works, it's what caused"
echo "    stale builds to survive full dev-server restarts before it was found and disabled."
exec bun run dev
