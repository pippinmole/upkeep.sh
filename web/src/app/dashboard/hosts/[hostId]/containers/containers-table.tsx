import { ImageScoreCell } from "@/components/image/score-cell";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { imageHref } from "@/lib/image-key";
import type { ContainerPort, HostContainerRow } from "@/lib/queries-docker";
import { formatDateTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

// Containers grouped by Compose project or Swarm stack, ungrouped last.
// Server-rendered plain tables: a host has tens of containers, and grouping
// doesn't fit the DataTable's flat model.

type Group = {
  key: string;
  kind: "compose" | "stack" | null;
  name: string | null;
  rows: HostContainerRow[];
};

function groupContainers(rows: HostContainerRow[]): Group[] {
  const groups = new Map<string, Group>();
  for (const r of rows) {
    const g: Omit<Group, "rows"> = r.swarmStack
      ? { key: `stack:${r.swarmStack}`, kind: "stack", name: r.swarmStack }
      : r.composeProject
        ? { key: `compose:${r.composeProject}`, kind: "compose", name: r.composeProject }
        : { key: "none", kind: null, name: null };
    let e = groups.get(g.key);
    if (!e) groups.set(g.key, (e = { ...g, rows: [] }));
    e.rows.push(r);
  }
  return [...groups.values()].sort((a, b) =>
    a.kind === null ? 1 : b.kind === null ? -1 : (a.name ?? "").localeCompare(b.name ?? ""),
  );
}

const STATE_STYLE: Record<string, string> = {
  running: "border-emerald-600/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200",
  restarting: "border-amber-500/50 text-amber-700 dark:text-amber-400",
  paused: "border-sky-500/40 text-sky-700 dark:text-sky-400",
  dead: "border-red-500/40 text-red-700 dark:text-red-400",
};

function StateCell({ c }: { c: HostContainerRow }) {
  if (!c.state) return <span className="text-muted-foreground">Unknown</span>;
  return (
    <div className="flex flex-col items-start gap-0.5">
      <Badge
        variant="outline"
        className={cn(
          "whitespace-nowrap capitalize",
          STATE_STYLE[c.state] ?? "text-muted-foreground",
        )}
      >
        {c.state}
      </Badge>
      {c.state === "running" && c.startedAt && (
        <span
          className="text-muted-foreground text-xs"
          title={`Started ${formatDateTime(c.startedAt)}`}
        >
          started {relativeTime(c.startedAt)}
        </span>
      )}
    </div>
  );
}

function ImageCell({ c }: { c: HostContainerRow }) {
  const title = [
    c.imageId && `Image ID: ${c.imageId}`,
    c.imageTags.length > 0 && `Tags: ${c.imageTags.join(", ")}`,
    c.imageDigests.length > 0 && `Digests: ${c.imageDigests.join(", ")}`,
    c.imageId &&
      c.imageTags.length === 0 &&
      "The image isn't tagged (or no longer listed) on this host",
  ]
    .filter(Boolean)
    .join("\n");
  // The configured reference can be a bare id (`docker run sha256:…`).
  const ref = c.image?.startsWith("sha256:") ? c.image.slice(7, 19) : c.image;
  return (
    <span className="block max-w-64 truncate font-mono text-xs" title={title || undefined}>
      {ref ?? <span className="text-muted-foreground">—</span>}
    </span>
  );
}

// Loopback / all-interfaces / a specific address. Neutral wording only:
// whether a port is reachable from outside depends on firewalls, which is
// the (later) exposure classification's job.
type Bind = "all" | "loopback" | "address";
function bindKind(ip: string | undefined): Bind {
  if (!ip || ip === "0.0.0.0" || ip === "::") return "all";
  if (ip.startsWith("127.") || ip === "::1") return "loopback";
  return "address";
}
const BIND_STYLE: Record<Bind, string> = {
  all: "border-amber-500/50 bg-amber-500/10 text-amber-800 dark:text-amber-300",
  loopback: "text-muted-foreground",
  address: "",
};
const BIND_TITLE: Record<Bind, string> = {
  all: "Published on all interfaces (0.0.0.0 / ::)",
  loopback: "Published on loopback only",
  address: "Published on a specific address",
};

function PortsCell({ ports }: { ports: ContainerPort[] }) {
  if (ports.length === 0) return <span className="text-muted-foreground">—</span>;
  // 0.0.0.0 and :: of the same mapping on one line.
  const merged = new Map<string, { ips: (string | undefined)[]; p: ContainerPort }>();
  for (const p of ports) {
    const k = `${p.host_port ?? ""}>${p.container_port}/${p.proto}:${bindKind(p.host_ip)}`;
    const m = merged.get(k);
    if (m) m.ips.push(p.host_ip);
    else merged.set(k, { ips: [p.host_ip], p });
  }
  return (
    <div className="flex flex-col items-start gap-1">
      {[...merged.values()].map(({ ips, p }) => {
        const target = `${p.container_port}/${p.proto}`;
        if (p.host_port === undefined || p.host_port === null) {
          return (
            <span
              key={`x:${target}`}
              className="text-muted-foreground font-mono text-xs"
              title="Exposed by the image but not published on the host"
            >
              {target} (not published)
            </span>
          );
        }
        const kind = bindKind(p.host_ip);
        const host = ips
          .map((ip) => `${ip?.includes(":") ? `[${ip}]` : (ip ?? "*")}:${p.host_port}`)
          .join(", ");
        return (
          <Badge
            key={`${host}>${target}`}
            variant="outline"
            className={cn("font-mono text-xs font-normal whitespace-nowrap", BIND_STYLE[kind])}
            title={BIND_TITLE[kind]}
          >
            {host} → {target}
          </Badge>
        );
      })}
    </div>
  );
}

const SPECIAL_MODES = new Set(["host", "none"]);

function NetworksCell({ c }: { c: HostContainerRow }) {
  const mode = c.networkMode;
  const special = mode && (SPECIAL_MODES.has(mode) || mode.startsWith("container:"));
  return (
    <div className="flex flex-col items-start gap-0.5 text-xs">
      {special ? (
        <span
          className="font-mono"
          title={
            mode === "host"
              ? "Host network mode: the container shares the host's network stack, so its sockets appear on the Listeners tab and nothing is published through Docker"
              : `Network mode ${mode}`
          }
        >
          {mode.startsWith("container:") ? `container:${mode.slice(10, 22)}` : `${mode} network`}
        </span>
      ) : c.networks && c.networks.length > 0 ? (
        c.networks.map((n) => (
          <span key={n} className="block max-w-56 truncate font-mono" title={n}>
            {n}
          </span>
        ))
      ) : (
        <span className="text-muted-foreground">{mode ?? "—"}</span>
      )}
    </div>
  );
}

const SOCKET_RE = /(^|\/)(docker|podman)\.sock$/;

// Bind mounts that hand the container the host: the Docker socket (full
// engine API) or the host's root filesystem.
function flags(c: HostContainerRow) {
  const out: { label: string; title: string }[] = [];
  if (c.privileged) {
    out.push({
      label: "Privileged",
      title: "Runs with --privileged: all capabilities and access to the host's devices",
    });
  }
  for (const m of c.mounts ?? []) {
    if (m.type !== "bind" || !m.source) continue;
    if (
      m.source === "/var/run/docker.sock" ||
      m.source === "/run/docker.sock" ||
      SOCKET_RE.test(m.source)
    ) {
      out.push({
        label: "Docker socket",
        title: `Bind-mounts ${m.source} at ${m.destination}${m.rw ? "" : " (read-only, which doesn't stop API calls)"}: full Docker API access, root-equivalent on the host`,
      });
    } else if (m.source === "/") {
      out.push({
        label: "Host root",
        title: `Bind-mounts the host's / at ${m.destination}${m.rw ? " read-write" : " read-only"}`,
      });
    }
  }
  return out;
}

function FlagsCell({ c }: { c: HostContainerRow }) {
  const fs = flags(c);
  const binds = (c.mounts ?? []).filter((m) => m.type === "bind");
  if (fs.length === 0) {
    return binds.length > 0 ? (
      <span
        className="text-muted-foreground text-xs"
        title={binds.map((m) => `${m.source} → ${m.destination}${m.rw ? "" : " (ro)"}`).join("\n")}
      >
        {binds.length} bind {binds.length === 1 ? "mount" : "mounts"}
      </span>
    ) : (
      <span className="text-muted-foreground">—</span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1">
      {fs.map((f) => (
        <Badge
          key={f.label}
          variant="outline"
          className="border-red-500/40 whitespace-nowrap text-red-700 dark:text-red-400"
          title={f.title}
        >
          {f.label}
        </Badge>
      ))}
    </div>
  );
}

function ContainerRow({ c }: { c: HostContainerRow }) {
  // Every detail column NULL: never successfully inspected.
  const known =
    c.ports !== null ||
    c.networks !== null ||
    c.networkMode !== null ||
    c.privileged !== null ||
    c.restartPolicy !== null ||
    c.mounts !== null;
  const sub = c.swarmServiceName ?? c.composeService;
  return (
    <TableRow>
      <TableCell>
        <div className="flex min-w-0 flex-col">
          <span className="font-mono text-sm" title={`Container ID ${c.id}`}>
            {c.name}
          </span>
          {sub && sub !== c.name && (
            <span className="text-muted-foreground text-xs">
              {c.swarmServiceName ? "service" : "compose service"} {sub}
            </span>
          )}
          {c.inspectError && known && (
            <span
              className="text-muted-foreground w-fit cursor-help text-xs underline decoration-dotted"
              title={`The latest push couldn't inspect this container: ${c.inspectError}. Details shown are from an earlier collection.`}
            >
              Partial: details may be out of date
            </span>
          )}
        </div>
      </TableCell>
      <TableCell>
        <StateCell c={c} />
      </TableCell>
      <TableCell>
        <ImageCell c={c} />
      </TableCell>
      <TableCell>
        {c.imageId ? (
          <ImageScoreCell
            score={c.imageScore}
            inspected={c.imagePlatform !== null}
            hasRepoDigest={c.imageDigests.length > 0}
            href={c.imagePlatform ? imageHref(c.imageId, { platform: c.imagePlatform }) : null}
          />
        ) : (
          <span className="text-muted-foreground">—</span>
        )}
      </TableCell>
      {known ? (
        <>
          <TableCell>
            <PortsCell ports={c.ports ?? []} />
          </TableCell>
          <TableCell>
            <NetworksCell c={c} />
          </TableCell>
          <TableCell className="text-xs whitespace-nowrap">
            {c.restartPolicy ?? <span className="text-muted-foreground">—</span>}
          </TableCell>
          <TableCell>
            <FlagsCell c={c} />
          </TableCell>
        </>
      ) : (
        <TableCell colSpan={4}>
          <span
            className="text-muted-foreground cursor-help text-xs underline decoration-dotted"
            title={
              c.inspectError
                ? `Inspecting this container failed: ${c.inspectError}`
                : "This container hasn't been inspected successfully yet"
            }
          >
            Details unavailable
          </span>
        </TableCell>
      )}
    </TableRow>
  );
}

export function ContainersTable({ rows }: { rows: HostContainerRow[] }) {
  const groups = groupContainers(rows);
  return (
    <div className="flex flex-col gap-4">
      {groups.map((g) => {
        const running = g.rows.filter((r) => r.state === "running").length;
        return (
          <section key={g.key} className="bg-card rounded-lg border">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b px-4 py-2.5 text-sm">
              <span className="font-medium">
                {g.kind === null ? (groups.length > 1 ? "Other containers" : "Containers") : g.name}
              </span>
              {g.kind && (
                <Badge variant="secondary" className="font-normal">
                  {g.kind === "stack" ? "Swarm stack" : "Compose project"}
                </Badge>
              )}
              <span className="text-muted-foreground">
                {running} running of {g.rows.length}
              </span>
            </div>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Image</TableHead>
                  <TableHead>Image vulnerabilities</TableHead>
                  <TableHead>Published ports</TableHead>
                  <TableHead>Networks</TableHead>
                  <TableHead>Restart</TableHead>
                  <TableHead>Flags</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {g.rows.map((c) => (
                  <ContainerRow key={c.id} c={c} />
                ))}
              </TableBody>
            </Table>
          </section>
        );
      })}
    </div>
  );
}
