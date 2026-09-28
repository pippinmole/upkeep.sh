import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { ContainerPort, DockerRangeEvent } from "@/lib/queries-docker";

// Container / image changes at one History boundary: range opens and
// closes of host_containers / host_images (migration 0013). A close + open
// of the same container id (or image id) at one boundary is one change
// (state, image, ports… or, for images, the tags); anything else is an
// add or a removal.

type FactKind = DockerRangeEvent["factKind"];

export type DockerChange =
  | { kind: "added" | "removed"; e: DockerRangeEvent }
  | {
      kind: "started" | "stopped" | "changed";
      from: DockerRangeEvent;
      to: DockerRangeEvent;
      diffs: string[];
    };

const ports = (ps: ContainerPort[] | null) =>
  ps === null
    ? null
    : ps
        .map((p) =>
          p.host_port === undefined || p.host_port === null
            ? `${p.container_port}/${p.proto}`
            : `${p.host_ip ?? "*"}:${p.host_port}→${p.container_port}/${p.proto}`,
        )
        .sort()
        .join(", ") || "none";

const shortId = (id: string | null) => (id?.startsWith("sha256:") ? id.slice(7, 19) : id);

function diffs(a: DockerRangeEvent, b: DockerRangeEvent): string[] {
  const out: string[] = [];
  const cmp = (label: string, x: unknown, y: unknown, show = true) => {
    const sx = x === null || x === undefined ? "unknown" : String(x);
    const sy = y === null || y === undefined ? "unknown" : String(y);
    if (sx !== sy) out.push(show ? `${label}: ${sx} → ${sy}` : `${label} changed`);
  };
  if (a.factKind === "images:docker") {
    cmp("tags", a.repoTags.join(", ") || "none", b.repoTags.join(", ") || "none");
    return out;
  }
  cmp("name", a.name, b.name);
  cmp("state", a.state, b.state);
  cmp("image", a.image, b.image);
  if (a.image === b.image) cmp("image id", shortId(a.imageId), shortId(b.imageId));
  cmp("published ports", ports(a.ports), ports(b.ports));
  cmp("networks", a.networks?.join(", "), b.networks?.join(", "));
  cmp("restart policy", a.restartPolicy, b.restartPolicy);
  cmp("privileged", a.privileged, b.privileged);
  cmp("mounts", JSON.stringify(a.mounts), JSON.stringify(b.mounts), false);
  return out;
}

export function pairDockerChanges(events: DockerRangeEvent[]): DockerChange[] {
  const groups = new Map<string, { opens: DockerRangeEvent[]; closes: DockerRangeEvent[] }>();
  for (const e of events) {
    const k = `${e.factKind}\0${e.key}`;
    let g = groups.get(k);
    if (!g) groups.set(k, (g = { opens: [], closes: [] }));
    (e.kind === "open" ? g.opens : g.closes).push(e);
  }
  const out: DockerChange[] = [];
  for (const g of groups.values()) {
    if (g.opens.length === 1 && g.closes.length === 1) {
      const from = g.closes[0];
      const to = g.opens[0];
      const d = diffs(from, to);
      const onlyState = d.length === 1 && d[0].startsWith("state:");
      const kind =
        onlyState && to.state === "running"
          ? "started"
          : onlyState && from.state === "running"
            ? "stopped"
            : "changed";
      out.push({ kind, from, to, diffs: d });
    } else {
      for (const e of g.closes) out.push({ kind: "removed", e });
      for (const e of g.opens) out.push({ kind: "added", e });
    }
  }
  const ev = (c: DockerChange) => ("e" in c ? c.e : c.to);
  return out.sort(
    (a, b) => ev(a).factKind.localeCompare(ev(b).factKind) || ev(a).name.localeCompare(ev(b).name),
  );
}

// "2 containers added · 1 image removed" pieces for the boundary header.
export function dockerSummary(changes: DockerChange[]): string[] {
  const counts = new Map<string, number>();
  for (const c of changes) {
    const e = "e" in c ? c.e : c.to;
    const k = `${e.factKind}:${c.kind}`;
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  const noun = (fk: FactKind, n: number) =>
    fk === "containers:docker"
      ? n === 1
        ? "container"
        : "containers"
      : n === 1
        ? "image"
        : "images";
  return [...counts].map(([k, n]) => {
    const [fk, kind] = k.split(":docker:") as [string, DockerChange["kind"]];
    return `${n} ${noun(`${fk}:docker` as FactKind, n)} ${kind}`;
  });
}

const BADGE: Record<DockerChange["kind"], { label: string; className: string }> = {
  added: {
    label: "Added",
    className: "border-emerald-500/40 text-emerald-700 dark:text-emerald-400",
  },
  removed: { label: "Removed", className: "border-red-500/40 text-red-700 dark:text-red-400" },
  started: {
    label: "Started",
    className: "border-emerald-500/40 text-emerald-700 dark:text-emerald-400",
  },
  stopped: {
    label: "Stopped",
    className: "border-amber-500/50 text-amber-700 dark:text-amber-400",
  },
  changed: { label: "Changed", className: "border-sky-500/40 text-sky-700 dark:text-sky-400" },
};

function describe(c: DockerChange): string {
  if ("diffs" in c) return c.diffs.join("; ") || "details changed";
  const e = c.e;
  if (e.factKind === "images:docker") {
    return [e.repoTags.join(", ") || "untagged", shortId(e.imageId)].join(" · ");
  }
  return [e.image, e.state].filter(Boolean).join(" · ");
}

export function DockerChangesTable({ changes }: { changes: DockerChange[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-28">Change</TableHead>
          <TableHead>Container / image</TableHead>
          <TableHead>Details</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {changes.map((c) => {
          const e = "e" in c ? c.e : c.to;
          const badge = BADGE[c.kind];
          return (
            <TableRow key={`${c.kind}:${e.factKind}:${e.key}`}>
              <TableCell>
                <Badge variant="outline" className={badge.className}>
                  {badge.label}
                </Badge>
              </TableCell>
              <TableCell>
                <div className="flex flex-col">
                  <span
                    className={
                      c.kind === "removed"
                        ? "text-muted-foreground font-mono text-sm line-through"
                        : "font-mono text-sm"
                    }
                    title={e.key}
                  >
                    {e.factKind === "images:docker" && e.name === e.key ? shortId(e.key) : e.name}
                  </span>
                  <span className="text-muted-foreground text-xs">
                    {e.factKind === "containers:docker" ? "Container" : "Image"}
                  </span>
                </div>
              </TableCell>
              <TableCell className="text-muted-foreground font-mono text-xs">
                {describe(c)}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}
