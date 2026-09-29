#!/usr/bin/env bash
# Checks (or sets) the agent image version pinned in the repo. Two pins
# must agree: web/src/lib/agent-image.ts (the dashboard's install command)
# and agent/docker-compose.example.yml. See docs/RELEASING.md.
#
#   scripts/check-version-pins.sh              the two pins agree
#   scripts/check-version-pins.sh 0.1.0        ...and equal 0.1.0 (a
#                                              leading "v" is accepted;
#                                              release.yml runs this with
#                                              the pushed tag)
#   scripts/check-version-pins.sh --set 0.2.0  rewrite both pins
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
image="ghcr.io/pippinmole/upkeep-agent"
files=(web/src/lib/agent-image.ts agent/docker-compose.example.yml)
semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'

# pin FILE: the tag after $image: in FILE (exactly one occurrence).
pin() {
  local found
  found="$(grep -oE "${image//./\\.}:[^\"[:space:]]+" "$root/$1" || true)"
  if [ "$(printf '%s\n' "$found" | grep -c .)" -ne 1 ]; then
    echo "error: expected exactly one ${image}:<version> in $1, found:" >&2
    printf '  %s\n' "${found:-(none)}" >&2
    exit 1
  fi
  printf '%s\n' "${found#"$image":}"
}

if [ "${1:-}" = "--set" ]; then
  new="${2:-}"
  new="${new#v}"
  if ! [[ "$new" =~ $semver ]]; then
    echo "usage: $0 --set X.Y.Z[-pre]" >&2
    exit 2
  fi
  for f in "${files[@]}"; do
    old="$(pin "$f")"
    sed -i.bak "s|${image}:${old}|${image}:${new}|" "$root/$f"
    rm -f "$root/$f.bak"
    echo "$f: $old -> $new"
  done
  exit 0
fi

want="${1:-}"
want="${want#v}"
status=0
first=""
for f in "${files[@]}"; do
  v="$(pin "$f")"
  echo "$f: $v"
  if ! [[ "$v" =~ $semver ]]; then
    echo "error: $f pins '$v', not an exact X.Y.Z version (never :latest)" >&2
    status=1
  fi
  if [ -z "$first" ]; then
    first="$v"
  elif [ "$v" != "$first" ]; then
    echo "error: $f pins $v but ${files[0]} pins $first; they must agree" >&2
    status=1
  fi
  if [ -n "$want" ] && [ "$v" != "$want" ]; then
    echo "error: $f pins $v but the release is $want." >&2
    echo "       Bump the pins first: scripts/check-version-pins.sh --set $want (docs/RELEASING.md)" >&2
    status=1
  fi
done
[ "$status" -eq 0 ] && echo "ok: agent image pins agree${want:+ with $want}"
exit "$status"
