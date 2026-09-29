#!/usr/bin/env bash
# Runs INSIDE the probe container, which run.sh starts in place of the
# agent with the compose example's own mounts, pid/network namespaces and
# hardening. Asserts what the agent container can reach.
#
#   probe.sh opt-out   the example as shipped: no host socket reachable
#   probe.sh opt-in    Docker socket line enabled: that socket works, and
#                      /host is still clean
set -u
mode=${1:?usage: probe.sh opt-out|opt-in}
fail=0
bad() { echo "FAIL: $*"; fail=1; }
ok() { echo "ok:   $*"; }

# Host control sockets (the agent's target.knownSockets, run/ side;
# var/run is an absolute symlink to /run and resolves into the container
# itself, so it is covered by the run/ entries and never tested directly).
known=(
  run/docker.sock
  run/containerd/containerd.sock
  run/podman/podman.sock
  run/systemd/private
  run/systemd/notify
  run/systemd/journal/socket
  run/dbus/system_bus_socket
  run/snapd.socket
  run/crio/crio.sock
  run/k3s/containerd/containerd.sock
  var/snap/lxd/common/lxd/unix.socket
  var/lib/lxd/unix.socket
  var/lib/incus/unix.socket
)
for p in "${known[@]}"; do
  if [ -e "/host/$p" ] || [ -L "/host/$p" ]; then bad "/host/$p is present"; fi
done
for p in /host/run/user/*/docker.sock /host/run/user/*/podman/podman.sock; do
  if [ -e "$p" ]; then bad "$p is present"; fi
done
[ "$fail" = 0 ] && ok "no known host socket under /host (${#known[@]} paths + run/user/*)"

# Walk /host for unix sockets without following symlinks. A socket on a
# different device than /host itself came through a nested mount (/run
# tmpfs, a separate /var ...), which only a recursive bind carries: fail.
# A socket on the host's root filesystem itself is carried even by the
# non-recursive bind; it depends on the host, not on the compose file, so
# it's listed but not failed (the agent's host_mount status flags it).
rootdev=$(stat -c %d /host)
walk=$(find /host -maxdepth 8 \
  \( -path /host/proc -o -path /host/sys -o -path /host/dev -o -path /host/snap \
     -o -path /host/var/lib/docker -o -path /host/var/lib/containerd \) -prune \
  -o -type s -printf '%D %p\n' 2>/dev/null)
nested=0
while read -r dev path; do
  [ -z "$path" ] && continue
  if [ "$dev" != "$rootdev" ]; then bad "socket on a nested mount: $path"; nested=$((nested + 1));
  else echo "note: socket on the host's root filesystem: $path"; fi
done <<<"$walk"
[ "$nested" = 0 ] && ok "walk of /host: no socket from a nested mount"

# Anything mounted under /host at all means the bind was recursive.
subs=$(awk '$5 ~ "^/host/" {print $5}' /proc/self/mountinfo | head -5)
if [ -n "$subs" ]; then bad "mounts nested under /host (recursive bind): ${subs//$'\n'/ }"; else ok "nothing mounted under /host"; fi

if curl -s --max-time 3 --unix-socket /host/run/docker.sock http://d/_ping >/dev/null 2>&1; then
  bad "connected to /host/run/docker.sock"
else
  ok "connect to /host/run/docker.sock fails"
fi

# The collectors' inputs are still there.
expect() { # expect <description> <test args...>
  local what=$1
  shift
  if "$@"; then ok "$what"; else bad "$what"; fi
}
expect "/host/etc/os-release readable" test -s /host/etc/os-release
expect "/host-extra/var/lib/dpkg/status readable" test -s /host-extra/var/lib/dpkg/status
expect "/host-extra/var/lib/apt present" test -d /host-extra/var/lib/apt
expect "/host-extra/run/systemd/system has units" test -n "$(ls -A /host-extra/run/systemd/system 2>/dev/null)"

if [ "$mode" = opt-in ]; then
  ping=$(curl -s --max-time 5 --unix-socket /var/run/docker.sock http://d/_ping)
  expect "opt-in: Docker reachable at /var/run/docker.sock (_ping returned '$ping')" test "$ping" = OK
fi

[ "$fail" = 0 ] && echo "PASS ($mode)" || echo "FAILED ($mode)"
exit "$fail"
