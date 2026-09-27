#!/usr/bin/env bash
# Builds and runs a real test agent on macOS (or any Docker host, including
# native Linux) using test-agent.Dockerfile — a genuine ubuntu:22.04-based
# image with its own real dpkg database and os-release, so it collects real
# facts without needing WSL or a host filesystem mount.
#
# Uses normal bridge networking + host.docker.internal instead of
# --network host, since host networking isn't reliably supported on Docker
# Desktop for Mac (unlike Linux, where it's native). --add-host is there so
# this also works unmodified if ever run on native Linux Docker, where
# host.docker.internal doesn't resolve automatically the way it does on
# Docker Desktop.
#
# Usage: test-agent-mac.sh [interval]
#   interval defaults to 30s, same reasoning as test-agent-windows.sh.
set -euo pipefail

INTERVAL="${1:-30s}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "==> Checking the dev API is reachable on :8080 (start it first if not — see up.sh)..."
if ! curl -s -o /dev/null http://localhost:8080/ 2>/dev/null; then
  echo "    WARNING: nothing answered on localhost:8080. Run up.sh first." >&2
fi

echo "==> Building the test agent image (real ubuntu base, not the scratch production image)..."
docker build -f .claude/skills/start-dev/scripts/test-agent.Dockerfile -t security-whatnot-agent-test ./agent

echo "==> Generating a fresh one-time enrollment token..."
# Same INSERT the real dashboard "Register agent" button runs — see the
# comment in test-agent-windows.sh for the full explanation.
TOKEN="$(node -e "console.log(require('crypto').randomBytes(24).toString('base64url'))")"
docker exec security-whatnot-dev-postgres-1 psql -U swuser -d security_whatnot -c \
  "INSERT INTO enrollment_tokens (token, user_id, expires_at) VALUES ('$TOKEN', (SELECT id FROM users LIMIT 1), now() + interval '1 hour');" \
  >/dev/null

echo "==> Running the test agent (Ctrl-C to stop; it will keep pushing every $INTERVAL)..."
echo "    Note: the agent and its host show up in /dashboard/agents as a random container ID"
echo "    (e.g. '8f4cee2f53bc'), not a real hostname — os.Hostname() just returns the"
echo "    container's own hostname, which Docker assigns from the container ID. That's"
echo "    fine for verifying the pipeline; it's just not a meaningful name."
docker run --rm \
  --add-host=host.docker.internal:host-gateway \
  -e SW_SERVER_URL=http://host.docker.internal:8080 \
  -e SW_ENROLLMENT_TOKEN="$TOKEN" \
  -e SW_INTERVAL="$INTERVAL" \
  security-whatnot-agent-test
