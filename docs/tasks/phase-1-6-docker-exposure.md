# Phase 1.6 — Docker inventory + host-side port exposure
Decided 2026-09-27 ([Port exposure](../decisions/port-exposure.md) and [Docker
collection](../decisions/docker-collection.md)). Generic Docker Engine support, including Swarm (managers
and workers), rootless Docker and Podman's Docker-compatible API; no
per-platform special-casing (Dokploy, Coolify…). Planned wire shape:
PROTOCOL.md "Docker sections". Order: the collector, then
storage/UI, then firewall + exposure on top.
- [x] Agent: Docker Engine API access through Docker's official Go client
      (`github.com/moby/moby/client`; decided 2026-09-28,
      [Docker collection](../decisions/docker-collection.md)) over the socket mounted into the
      agent container (`SW_DOCKER_SOCKET`, default
      `/var/run/docker.sock`), with API version negotiation and a pinned
      minimum. Collectors use it only through a small internal interface
      holding the reads they need: ping, version, info, container
      list/inspect, image list/inspect, network list, and on managers
      service/task/node list. Never logs, archive/export, image save,
      attach/exec, secrets or configs.
- [x] Agent: Docker collectors via that interface (`skipped` with a reason
      when the socket isn't mounted, so "no Docker" and "Docker not
      enabled" are normal states, distinct from `error`; `skipped` with
      a distinct reason on remote (SSH) targets, see below):
      `docker_engine` (version, API version, storage driver / image
      store, rootless, Swarm node id / cluster id / role),
      `docker_containers`, `docker_images`, `docker_networks`, and
      `swarm_services` (managers only; `skipped` on workers). The agent's
      wire types are the allowlist: only declared fields are sent (never
      `Env`, command lines, Swarm secret/config references), and labels
      only by exact key for Compose / stack / Swarm plus the
      `org.opencontainers.image.*` prefix (PROTOCOL.md "Never sent"),
      because labels routinely carry secrets (e.g. reverse-proxy
      basic-auth hashes). Mount sources only for bind mounts. SDK structs are
      mapped onto these wire types, never sent as-is. Caps + `truncated`
      like the other collectors.
- [x] Docker is collected **only on hosts with their own agent**
      ([Docker collection](../decisions/docker-collection.md)): remote (SSH) targets report the
      Docker collectors `skipped` with reason "remote host" (their key is
      read-only SFTP, which can't reach the socket). The dashboard must
      make this obvious rather than showing an empty list, with three
      distinct states on the Containers / Images tabs and anywhere else
      Docker data appears (fleet images page, exposure):
      - **Remote host**: "Docker data needs an agent on this host. This
        host is collected over SSH by <agent>, which can only read
        files." Link to installing the agent on it.
      - **Local agent, socket not mounted**: "Docker collection isn't
        enabled on this agent", with the socket mount line and what it
        grants.
      - **Enabled, nothing running**: a normal empty state.
      Also: the "Reach it from an existing agent" option in the Add host
      dialog lists what remote collection doesn't cover (Docker,
      listeners, port exposure), so it's clear before the choice; and the
      host header shows a "Remote (SSH)" badge next to the collecting
      agent. (Done: the Add host list, the header's "Collected by" line
      with the badge, and the tabs' shared `docker-collection-state.tsx`,
      which also covers engine unreachable, collector error and an older
      agent build that reports no Docker status.)
- [x] Compose example + dashboard `docker run` line: Docker collection
      is **opt-in**, one socket mount with a comment saying plainly what
      it grants (full Docker API access, i.e. root-equivalent; the agent
      only makes the reads listed above). Docs for rootless Docker
      (`$XDG_RUNTIME_DIR/docker.sock`) and Podman (`podman.socket`).
      Register agent dialog: "Collect Docker containers and images"
      checkbox (default off); README "Docker collection (optional)".
      With `cap_drop: ALL` the agent (uid 0) connects only to sockets
      root owns; others need `group_add` with the socket's gid.
- [ ] Running the agent itself under rootless Docker / rootless Podman
      (as opposed to mounting a rootless engine's socket into a rootful
      agent, which is documented): `network_mode: host` is rootlesskit's
      network namespace there, not the host's, and `pid: host` / the
      `/:/host` mount behave differently, so listeners (and likely
      deleted-libs) would describe the wrong namespace. Verify on a real
      host; either document it as unsupported or detect and report the
      affected collectors `skipped`. Also unverified there: that
      rootlesskit honours the non-recursive `/` bind (the host's `/run`
      would otherwise be reachable; the `host_mount` self-check would
      report it), and that `/host-extra` binds of root-owned paths work.
- [x] Make opting out real (done 2026-09-29): `/:/host:ro` was a
      recursive bind, so the host's `/run/docker.sock` was reachable at
      `/host/run/docker.sock` whether or not the socket was mounted
      (`:ro` doesn't stop `connect()`). Reproduced 2026-09-27 (Docker
      Desktop, Engine 29.8.0) and again on Ubuntu 24.04 / Engine 29.8.1
      with the agent's exact hardening: `GET /version` and `POST
      /containers/create` succeeded; containerd, D-Bus and systemd's
      private socket were present and accepted connections. Now: the
      host's `/` is bound non-recursively at `/host` (compose `bind:
      recursive: disabled`, `docker run --mount
      ...,bind-recursive=disabled`), and `var/lib/dpkg`, `var/lib/apt`
      and `run/systemd/system` are bound read-only under `/host-extra`
      with `create_host_path: false` (`target.ExtraPaths`, overlaid by
      `hostFS` in `agent/internal/target/hostmounts.go`; a bind nested
      inside the read-only `/host` can't be created when its parent is a
      separate mount). `/run` and `/var` are never bound whole.
      `reboot_required` no longer needs `/run/reboot-required`: it is
      derived from the running kernel vs installed `linux-image-*`
      packages when the host's `/run` isn't visible (decided by device,
      `target/device.go`), `skipped` when neither signal can decide, with
      the new optional wire field `reboot_required_source`. Missing paths
      are errors naming the mount to check (`target.NotVisible`). A
      socket self-check (`target/sockets.go`: a known list plus a walk of
      `run/`, symlinks resolved against the host root) runs at startup
      (`WARN:` before enrollment), as the `host_mount` collector status,
      and as `agent check-mounts`. The Register agent dialog builds its
      mount lines from `web/src/lib/host-mounts.ts`, which
      `host-mounts.test.ts` checks against the compose example. CI:
      `.github/workflows/host-mount.yml` ("Agent host mount (no host
      sockets)") runs `agent/test/host-mount/run.sh` on the compose
      example itself, opt-out and opt-in; it fails on the old recursive
      mount. Docker versions: the engine has honoured non-recursive binds
      since 19.03 (tested 24.0.9 and 29.8.1, with Compose v5.5.1); the
      docker CLI spells it `bind-recursive=disabled` from 25 and
      `bind-nonrecursive=true` before (each rejects the other's
      spelling). Not verified: sockets on the root filesystem itself
      (e.g. the LXD snap's socket when `/var` isn't separate) stay
      reachable under a non-recursive bind; `host_mount` flags them, but
      no LXD host was tested.
- [ ] Host mount follow-ups: sockets on the host's root filesystem
      itself (the LXD snap's `/var/snap/lxd/common/lxd/unix.socket`, or
      `/var/lib/incus/unix.socket`, when `/var` isn't separate) remain
      reachable through the non-recursive bind; `host_mount` reports them
      with a different message, but nothing hides them yet (a bind of an
      empty directory over them, or a documented "don't run the agent
      container on LXD hosts"). Verify on a host with LXD. Dashboard: a
      label for `host_mount` in `COLLECTOR_LABELS`
      (`web/src/lib/host-page.ts`) and a banner on the host page when it
      is `error`, since it means the agent can reach Docker with Docker
      collection off.
- [x] Migration + ingest on the validity-range pattern (like
      `host_services`; done 2026-09-28, migration 0013, DOMAIN_MODEL.md
      §4.5 "Docker"): `container_images` interned fleet-wide by image
      ID (content-addressed: OS/arch, created, layer diff IDs, OCI
      labels); `host_images` (image present on a host, with that host's
      repo tags + repo digests); `host_containers` (keyed by container
      ID: name, image ref as configured + image ID actually run, state,
      started at, compose project/service, Swarm service/task/stack,
      published ports, networks, network mode, privileged, restart
      policy, mount types/paths); `swarm_services` per Swarm cluster
      (from any manager's push: name, image, mode/replicas, published
      ports with ingress/host mode). Per-kind set hashes in
      `host_fact_state`, never closed when the collector isn't `ok`.
- [x] Dashboard: host **Containers** tab (grouped by compose project or
      Swarm stack, published ports, image, state) and **Images** tab;
      containers/images changes on the History tab; fleet
      `/dashboard/images` ("which hosts run image X / digest Y") and a
      Swarm cluster view (services → nodes/tasks).
- [ ] Agent: `firewall` collector, file reads only (live netfilter state
      needs `CAP_NET_ADMIN`, which the agent won't get): ufw enabled
      (`/etc/ufw/ufw.conf`), default policies (`/etc/default/ufw`),
      rules (`/etc/ufw/user.rules`, `user6.rules`); Docker's
      `/etc/docker/daemon.json` (`iptables`, `ip`, `userland-proxy`,
      `data-root`). nftables / firewalld / raw iptables → reported as
      "other firewall" (unknown), not guessed.
- [ ] Server: exposure classification per open listener, from
      `host_listeners` + Docker published ports + Swarm published ports +
      firewall facts: local-only; **published by Docker (host firewall
      doesn't apply: Docker's rules are evaluated before ufw's)**; no
      host firewall; allowed by ufw; blocked by ufw; unknown (other
      firewall, Docker with `userland-proxy: false` and no Docker data).
      A listener owned by `docker-proxy` or `dockerd` on a wildcard
      address counts as Docker-published even without the Docker
      collector. Wording is "not protected by the host firewall", never
      "public": provider firewalls (e.g. Hetzner Cloud) are invisible to
      the agent. Remediation text differs per class (bind to
      `127.0.0.1:` / `DOCKER-USER` rules for Docker; a ufw rule
      otherwise).
- [ ] Exposure events (`exposure.port_exposed` / `exposure.port_closed`)
      on class transitions, through the existing alerting pipeline (a
      new event type + `Event` object, no dispatch changes); ignore
      expected ports per rule (e.g. 80/443 on a reverse proxy). Replace
      `TODO(phase 1, exposure)` in `ingest/handler.go`.
