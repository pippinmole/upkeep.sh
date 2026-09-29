# Docker collection: Engine API from the agent, opt-in socket mount

Considered (2026-09-27): (1) the Docker Engine API over
`/var/run/docker.sock`; (2) reading Docker's on-disk state under
`/var/lib/docker/containers/<id>/{config.v2,hostconfig}.json` through
the existing `/:/host:ro` mount, like the systemd collector avoids D-Bus.

**Decided: (1).** On-disk state can't cover the scope we want: Swarm
service definitions (published ingress ports, replicas) live only in
managers' encrypted Raft store; image metadata is in different places for
the classic graphdriver store and the containerd image store
(increasingly the default for new installs), the latter in containerd's
locked metadata database; rootless Docker, a moved `data-root` and
Podman each need special handling. The API is documented and versioned,
covers containers, images, networks, Swarm services/tasks/nodes, and
Podman serves a compatible one. We support Docker and Swarm generically,
not Dokploy or Coolify specifically.

Access to the API is root on the host (anything that can talk to it can
start a privileged container); a `:ro` mount of a socket doesn't
restrict it, and there is no read-only mode for the socket. Two ways to
limit that were rejected:

- **An allowlisting proxy sidecar** holding the socket, with no network,
  serving read endpoints to the agent. Rejected: the realistic way the
  agent gets compromised is a malicious release (stolen publish token,
  CI or dependency compromise), and the proxy ships from the same
  pipeline, so it falls with the agent. Against a compromised platform
  server steering agents, agent code that only ever calls a fixed list
  of read endpoints protects just as well, since the server can only
  trigger what the agent's code does. What remains is arbitrary code
  execution inside a Go binary, the least likely case. Not worth the
  extra moving part.
- **A native (systemd) agent** as an unprivileged user with
  `CAP_DAC_READ_SEARCH`: tested to read every file yet be denied
  `connect()` on `docker.sock` (connecting needs write permission on the
  socket). Rejected for UX: users deploy everything through a compose
  file in their panel, and the socket still needs the privileged
  `docker` group for Docker data.

So: **the socket is mounted into the agent container, opt-in**, and the
boundary is the agent's own code: the collectors only ever call a fixed
list of read endpoints (not "GET-only": `GET /containers/{id}/archive`,
`/export`, `/images/{id}/get`, `/logs` and `/configs/{id}` all leak
data), and wire types only carry declared fields and allowlisted label
prefixes, because env and labels hold secrets. This is the same trust model as other monitoring agents that
mount the socket (Datadog, Netdata, cAdvisor), and we say so plainly:
with Docker enabled the agent is root-equivalent and "read-only" means
"only makes read calls, by design". The effort goes into release
supply chain instead (signed images, SBOM and provenance, versioned tags
rather than `:latest`, scoped publish tokens; [cross-cutting gaps](../tasks/cross-cutting-gaps.md)), which protects
every host whether or not Docker is enabled.

Found while deciding this: the original `/:/host:ro` mount was
recursive, so `/host/run/docker.sock` was reachable, and was shown to
allow `POST /containers/create` under the agent's exact hardening. The
agent code never used it, but it meant opting out of Docker wasn't real.
**Fixed** ([Phase 1.6](../tasks/phase-1-6-docker-exposure.md), "Make
opting out real"): the host's `/` is now bound non-recursively
(`bind: recursive: disabled`), so the `/run` tmpfs and its sockets
(docker.sock, containerd, D-Bus, systemd) aren't carried into `/host`.
The few directories the collectors read from other mounts
(`var/lib/dpkg`, `var/lib/apt`, `run/systemd/system`) are bound one by
one under `/host-extra`, and `/run/reboot-required` is replaced by a
pending reboot derived from the kernel packages. A regression shows up:
the agent logs a startup `WARN:` and reports the
`host_mount` collector as an error when any host socket is reachable
under `/host` (`agent check-mounts` does the same by hand), and the
`Host mount` CI workflow runs that check and a socket probe against
`agent/docker-compose.example.yml` itself. With the Docker opt-in, the
socket is mounted at its own path outside `/host`, which is the only
Docker access the agent has.

**Client: Docker's official Go client** (see the package below),
decided 2026-09-28 by the user, replacing a hand-written GET-only
client. A hand-written client only protects against someone running
arbitrary code in the agent, and anyone who can do that can talk to the
mounted socket directly anyway. Against a compromised server, what
counts is which calls the agent's code makes, not which calls exist in
the binary. So the SDK sits behind a small internal interface holding
only the read calls the collectors need, and SDK structs are mapped onto
our own wire types (the field and label allowlist), never serialized
as-is.

The package is **`github.com/moby/moby/client`** (API types in
`github.com/moby/moby/api`), the Engine API client the `docker` CLI
itself uses; `github.com/docker/docker/client` is its older module path.
Not `github.com/docker/go-sdk` (considered 2026-09-28): that is a v0.x
convenience layer over the same client that resolves Docker contexts,
`DOCKER_HOST` and `~/.docker/config.json` and adds pull/run helpers,
none of which a read-only collector needs, and the discovery conflicts
with the rule that the agent only ever dials `SW_DOCKER_SOCKET`.

**Docker is collected only on hosts with their own agent.** Remote (SSH)
hosts get `skipped`: their key is pinned to read-only SFTP, and SFTP
can't connect to a unix socket. The alternatives were considered and
not taken: `DOCKER_HOST=ssh://` needs exec on the remote host
(`docker system dial-stdio`); SSH stream-local forwarding to the socket
needs forwarding enabled on the key (OpenSSH has no per-key allowlist
for unix sockets) and the SSH user in the remote `docker` group. Either
would make one compromised agent root on every remote host it collects,
where today it can only read files there. A host running Docker can run
the agent container, so the fix for a remote host is "install the agent
there", and the dashboard says so wherever Docker data would appear.
On a Swarm manager, services, tasks and nodes cover the whole cluster,
but per-node containers and images still need an agent on each node.
