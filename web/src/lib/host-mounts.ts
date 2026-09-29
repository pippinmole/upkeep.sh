// The read-only host filesystem mounts the agent container gets, shared by
// the Register agent dialog's `docker run` snippet and checked against
// agent/docker-compose.example.yml (host-mounts.test.ts). Kept in step
// with target.ExtraPaths in the agent.
//
// The host's / is bound NON-recursively so no socket on the /run tmpfs
// (docker.sock, containerd, D-Bus, systemd) is reachable under /host — a
// plain `-v /:/host:ro` is recursive and would expose them, making opting
// out of Docker meaningless. Directories the collectors read that sit on a
// separate mount (/var, the /run tmpfs) are bound one by one under
// /host-extra. Requires Docker Engine 25+ (bind-recursive=disabled).
export const HOST_EXTRA_PATHS = ["var/lib/dpkg", "var/lib/apt", "run/systemd/system"];

export const HOST_MOUNTS: string[] = [
  "--mount type=bind,src=/,dst=/host,readonly,bind-recursive=disabled",
  ...HOST_EXTRA_PATHS.map((p) => `--mount type=bind,src=/${p},dst=/host-extra/${p},readonly`),
];
