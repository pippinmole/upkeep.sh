#!/usr/bin/env bash
# Builds the real agent binary and runs it inside WSL2 against the local
# dev stack, so it collects facts from a genuine Linux filesystem
# (/etc/os-release, a real dpkg database) instead of the empty scratch
# image the production Dockerfile produces.
#
# Usage: test-agent-windows.sh [wsl-distro-name] [interval]
#   wsl-distro-name defaults to "Ubuntu" (must be Debian/Ubuntu-family for
#   the dpkg-based package collector to find anything; check with `wsl -l -v`)
#   interval defaults to 30s — short, since this is for one-off testing,
#   not a real deployment (real deployments use SW_INTERVAL=15m or so).
# Env: SW_TEST_USER_EMAIL = the dashboard account to enroll into (required
#   when the dev DB has more than one user; see enroll-token.sh).
set -euo pipefail

DISTRO="${1:-Ubuntu}"
INTERVAL="${2:-30s}"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

echo "==> Checking the dev API is reachable on :8080 (start it first if not — see up.sh)..."
if ! curl -s -o /dev/null http://localhost:8080/ 2>/dev/null; then
  echo "    WARNING: nothing answered on localhost:8080. Run up.sh first." >&2
fi

echo "==> Building the agent image (picks up any local source changes)..."
docker build -t security-whatnot-agent ./agent

echo "==> Extracting the static Linux binary from the image..."
rm -f .agent-test-binary
docker create --name sw-agent-extract security-whatnot-agent >/dev/null
docker cp sw-agent-extract:/agent ./.agent-test-binary
docker rm sw-agent-extract >/dev/null

echo "==> Copying the binary into WSL ($DISTRO)..."
# git rev-parse can hand back either MSYS-style (/c/projects/...) or
# Windows-style (C:/projects/... or C:\projects\...) paths depending on
# the exact bash/git combination — WSL2 needs /mnt/c/projects/... either
# way, so normalize backslashes first, then convert whichever drive-letter
# form we got instead of assuming one.
REPO_ROOT_NORM="$(echo "$REPO_ROOT" | tr '\\' '/')"
case "$REPO_ROOT_NORM" in
  /[A-Za-z]/*)
    WSL_REPO_ROOT="/mnt/$(echo "$REPO_ROOT_NORM" | sed -E 's#^/([A-Za-z])/#\L\1/#')"
    ;;
  [A-Za-z]:/*)
    WSL_REPO_ROOT="/mnt/$(echo "$REPO_ROOT_NORM" | sed -E 's#^([A-Za-z]):/#\L\1/#')"
    ;;
  *)
    echo "Couldn't translate '$REPO_ROOT' to a WSL path — expected a drive-letter path." >&2
    exit 1
    ;;
esac
wsl -d "$DISTRO" -- bash -lc "mkdir -p ~/sw-agent-test/data && cp '$WSL_REPO_ROOT/.agent-test-binary' ~/sw-agent-test/agent && chmod +x ~/sw-agent-test/agent"

echo "==> Ensuring /host -> / symlink exists in WSL (the agent's collectors hardcode"
echo "    /host/... paths matching its production Docker bind-mount layout; this makes"
echo "    a bare binary run see the WSL distro's own real filesystem at that path)..."
wsl -d "$DISTRO" -u root -- bash -lc 'test -L /host && [ "$(readlink /host)" = "/" ] || ln -sfn / /host'

echo "==> Generating a fresh one-time enrollment token..."
# Same INSERT the dashboard's "Register agent" button runs; enroll-token.sh
# picks the account (SW_TEST_USER_EMAIL, or the only user) so the host shows
# up for the user you sign in as.
TOKEN="$(bash .claude/skills/start-dev/scripts/enroll-token.sh)"

echo "==> Running the agent in WSL (Ctrl-C to stop; it will keep pushing every $INTERVAL)..."
wsl -d "$DISTRO" -- bash -lc "cd ~/sw-agent-test && SW_SERVER_URL=http://localhost:8080 SW_ENROLLMENT_TOKEN=$TOKEN SW_DATA_DIR=\$HOME/sw-agent-test/data SW_INTERVAL=$INTERVAL ./agent"
