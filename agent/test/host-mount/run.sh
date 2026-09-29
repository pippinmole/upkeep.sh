#!/usr/bin/env bash
# Checks what the agent container can reach on the host, using the
# compose example itself (so the check can't drift from the docs).
#
#   agent/test/host-mount/run.sh [compose-file]
#
# compose-file defaults to agent/docker-compose.example.yml. It needs
# Docker with Compose and a systemd host (the example binds
# /run/systemd/system). Exit 0 only if every step passes:
#   1. opt-out (as shipped): `agent check-mounts` exits 0, and the probe
#      finds no host socket under /host and can't connect to
#      /host/run/docker.sock;
#   2. opt-in (the Docker socket line uncommented): the probe reaches
#      Docker at /var/run/docker.sock, /host is still clean, and
#      `agent check-mounts` still exits 0.
# Set SKIP_BUILD=1 to reuse already built upkeep-agent:ci and
# upkeep-hostmount-probe images.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
agent_dir=$(cd "$here/../.." && pwd)
compose=$(realpath "${1:-$agent_dir/docker-compose.example.yml}")
work=$(mktemp -d)
project=upkeep-hostmount-$$
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  docker compose -p "$project" -f "$compose" down -v --remove-orphans >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT

if [ -z "${SKIP_BUILD:-}" ]; then
  echo "== build"
  docker build -q -t upkeep-agent:ci --build-arg VERSION=host-mount-ci "$agent_dir" >/dev/null || exit 1
  docker build -q -t upkeep-hostmount-probe -f "$here/probe.Dockerfile" "$here" >/dev/null || exit 1
fi

cat >"$work/agent.yml" <<'EOF'
services:
  upkeep-agent:
    image: upkeep-agent:ci
    restart: "no"
EOF
cat >"$work/probe.yml" <<EOF
services:
  upkeep-agent:
    image: upkeep-hostmount-probe
    restart: "no"
    entrypoint: ["bash", "/probe.sh"]
    volumes:
      - $here/probe.sh:/probe.sh:ro
EOF

# The opt-in variant: the example with its Docker socket line enabled.
optin="$work/compose.opt-in.yml"
sed 's|^      # - /var/run/docker.sock:/var/run/docker.sock$|      - /var/run/docker.sock:/var/run/docker.sock|' "$compose" >"$optin"
if cmp -s "$compose" "$optin"; then
  echo "FAIL: the opt-in line '# - /var/run/docker.sock:/var/run/docker.sock' is not in $compose"
  exit 1
fi

status=0
step() { # step <name> <compose file> <override> [args...]
  local name=$1 file=$2 override=$3
  shift 3
  echo "== $name"
  docker compose -p "$project" -f "$file" -f "$override" run --rm upkeep-agent "$@" 2>&1 \
    | grep -v -E '^ *(Volume|Container|Network) '
  local rc=${PIPESTATUS[0]}
  if [ "$rc" = 0 ]; then echo "-- $name: pass"; else echo "-- $name: FAIL (exit $rc)"; status=1; fi
}

step "opt-out: agent check-mounts" "$compose" "$work/agent.yml" check-mounts
step "opt-out: probe" "$compose" "$work/probe.yml" opt-out
step "opt-in: probe" "$optin" "$work/probe.yml" opt-in
step "opt-in: agent check-mounts" "$optin" "$work/agent.yml" check-mounts

[ "$status" = 0 ] && echo "host mount check: PASS" || echo "host mount check: FAIL"
exit "$status"
