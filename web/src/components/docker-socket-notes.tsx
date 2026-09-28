// What mounting the Docker socket into the agent grants, and where the
// socket lives on rootless Docker / Podman (DECISIONS.md "Docker
// collection"). Shared by the Register agent dialog's opt-in checkbox and
// the host Containers / Images tabs' "not enabled" state, so both say the
// same thing.

export const DOCKER_SOCKET_MOUNT = "-v /var/run/docker.sock:/var/run/docker.sock";

export function DockerSocketGrant() {
  return (
    <>
      Mounts the Docker socket into the agent. That is full Docker API access, which is
      root-equivalent on the host. The agent only makes read calls, by design (containers, images,
      networks, Swarm services; never logs, exec, secrets or environment variables).
    </>
  );
}

export function DockerSocketAlternatives() {
  return (
    <details className="text-muted-foreground text-xs">
      <summary className="hover:text-foreground cursor-pointer select-none">
        Rootless Docker or Podman?
      </summary>
      <div className="mt-1 flex flex-col gap-1 text-left leading-relaxed">
        <p>Replace the left side of the socket mount with the socket&apos;s path on the host:</p>
        <ul className="list-disc pl-4">
          <li>
            Rootless Docker: <code>$XDG_RUNTIME_DIR/docker.sock</code>, e.g.{" "}
            <code>/run/user/1000/docker.sock</code>
          </li>
          <li>
            Podman: enable <code>podman.socket</code> first, then{" "}
            <code>/run/podman/podman.sock</code> (rootful) or{" "}
            <code>$XDG_RUNTIME_DIR/podman/podman.sock</code> (rootless)
          </li>
        </ul>
        <p>
          If that socket isn&apos;t owned by root, also add{" "}
          <code>--group-add &lt;the socket&apos;s group id&gt;</code> (
          <code>stat -c %g &lt;socket&gt;</code>): the agent drops all capabilities, so it
          can&apos;t bypass the socket&apos;s permissions.
        </p>
      </div>
    </details>
  );
}
