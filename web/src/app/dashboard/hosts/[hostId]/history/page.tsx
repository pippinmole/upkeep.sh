import type { Metadata } from "next";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostHistory, type RangeEvent } from "@/lib/queries-inventory";
import { param, parseAt, type SearchParams } from "@/lib/search-params";
import { formatDate, formatDateTime } from "@/lib/time";

const BOUNDARIES_PER_PAGE = 20;

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `History · ${hostTitle(host)}` };
}

type Change =
  | { kind: "installed"; e: RangeEvent }
  | { kind: "removed"; e: RangeEvent }
  // A range close + open of the same (ecosystem, name, arch) at the same
  // boundary. Upgrade vs downgrade needs ecosystem version semantics
  // (dpkg ordering for deb), which neither SQL nor this page implements,
  // so it is shown as "changed". P1b's Go debversion package can classify
  // it (see DOMAIN_MODEL.md §3.4).
  | { kind: "changed"; from: RangeEvent; to: RangeEvent };

function pairChanges(events: RangeEvent[]): Change[] {
  const groups = new Map<string, { opens: RangeEvent[]; closes: RangeEvent[] }>();
  for (const e of events) {
    const k = `${e.ecosystem}\0${e.name}\0${e.arch}`;
    let g = groups.get(k);
    if (!g) groups.set(k, (g = { opens: [], closes: [] }));
    (e.kind === "open" ? g.opens : g.closes).push(e);
  }
  const out: Change[] = [];
  for (const g of groups.values()) {
    // Only an unambiguous 1:1 pair is a change. Anything else (an
    // ecosystem allowing several versions of one name side by side) is
    // shown as the raw installs/removals.
    if (g.opens.length === 1 && g.closes.length === 1) {
      out.push({ kind: "changed", from: g.closes[0], to: g.opens[0] });
    } else {
      for (const e of g.closes) out.push({ kind: "removed", e });
      for (const e of g.opens) out.push({ kind: "installed", e });
    }
  }
  const name = (c: Change) => (c.kind === "changed" ? c.to : c.e);
  return out.sort(
    (a, b) => name(a).name.localeCompare(name(b).name) || name(a).arch.localeCompare(name(b).arch),
  );
}

const KIND_BADGE: Record<Change["kind"], { label: string; className: string }> = {
  installed: {
    label: "Installed",
    className: "border-emerald-500/40 text-emerald-700 dark:text-emerald-400",
  },
  removed: {
    label: "Removed",
    className: "border-red-500/40 text-red-700 dark:text-red-400",
  },
  changed: {
    label: "Changed",
    className: "border-sky-500/40 text-sky-700 dark:text-sky-400",
  },
};

function PackageCell({ e }: { e: RangeEvent }) {
  return (
    <div className="flex flex-col">
      <Link
        href={`/dashboard/packages/${encodeURIComponent(e.name)}`}
        className="font-medium hover:underline"
      >
        {e.name}
      </Link>
      {e.sourceName && e.sourceName !== e.name && (
        <span className="text-muted-foreground text-xs">src: {e.sourceName}</span>
      )}
    </div>
  );
}

export default async function HostHistoryPage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}) {
  const { hostId } = await params;
  const sp = await searchParams;
  const { userId, host } = await requireHost(hostId);
  const before = parseAt(param(sp, "before"));

  const { boundaries, nextBefore } = await getHostHistory(userId, host.id, {
    before,
    limit: BOUNDARIES_PER_PAGE,
  });
  const base = `/dashboard/hosts/${host.id}`;

  if (boundaries.length === 0) {
    return (
      <div className="bg-card text-muted-foreground rounded-lg border px-6 py-12 text-center text-sm">
        {before
          ? "No older package changes."
          : "No package changes have been recorded for this host yet."}
      </div>
    );
  }

  const days = boundaries.map((b) => formatDate(b.at));
  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground text-sm">
        Package changes per applied inventory, newest first. Times are the snapshot&apos;s
        collection time.
      </p>
      {boundaries.map((b, i) => {
        const baseline = new Set(b.baselineEcosystems);
        const baselineCount = new Map<string, number>();
        const rest: RangeEvent[] = [];
        for (const e of b.events) {
          if (e.kind === "open" && baseline.has(e.ecosystem)) {
            baselineCount.set(e.ecosystem, (baselineCount.get(e.ecosystem) ?? 0) + 1);
          } else {
            rest.push(e);
          }
        }
        const changes = pairChanges(rest);
        const counts = { installed: 0, removed: 0, changed: 0 };
        for (const c of changes) counts[c.kind]++;
        const day = days[i];
        const showDay = i === 0 || day !== days[i - 1];

        return (
          <section key={b.at} className="flex flex-col gap-2">
            {showDay && <h2 className="mt-2 text-sm font-semibold">{day}</h2>}
            <div className="bg-card rounded-lg border">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                  <span className="font-medium">{formatDateTime(b.at)}</span>
                  <span className="text-muted-foreground">
                    {[
                      ...[...baselineCount].map(
                        ([eco, n]) => `initial ${eco} inventory: ${n} packages`,
                      ),
                      counts.installed && `${counts.installed} installed`,
                      counts.changed && `${counts.changed} changed`,
                      counts.removed && `${counts.removed} removed`,
                    ]
                      .filter(Boolean)
                      .join(" · ")}
                  </span>
                </div>
                <Link
                  href={`${base}/packages?at=${encodeURIComponent(b.at)}`}
                  className="text-muted-foreground hover:text-foreground text-xs hover:underline"
                >
                  Inventory after this change
                </Link>
              </div>
              {changes.length > 0 && (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-28">Change</TableHead>
                      <TableHead>Package</TableHead>
                      <TableHead>Version</TableHead>
                      <TableHead>Arch</TableHead>
                      {/* P1b: "Security effect" (fixed / introduced CVEs) */}
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {changes.map((c) => {
                      const e = c.kind === "changed" ? c.to : c.e;
                      const badge = KIND_BADGE[c.kind];
                      return (
                        <TableRow key={`${c.kind}:${e.ecosystem}:${e.name}:${e.arch}:${e.version}`}>
                          <TableCell>
                            <Badge variant="outline" className={badge.className}>
                              {badge.label}
                            </Badge>
                          </TableCell>
                          <TableCell>
                            <PackageCell e={e} />
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {c.kind === "changed" ? (
                              <>
                                <span className="text-muted-foreground">{c.from.version}</span>
                                {" → "}
                                {c.to.version}
                              </>
                            ) : c.kind === "removed" ? (
                              <span className="text-muted-foreground line-through">
                                {c.e.version}
                              </span>
                            ) : (
                              c.e.version
                            )}
                          </TableCell>
                          <TableCell className="text-muted-foreground">{e.arch || "—"}</TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              )}
            </div>
          </section>
        );
      })}
      <div className="flex gap-2 py-2">
        {before && (
          <Button asChild variant="outline" size="sm">
            <Link href={`${base}/history`}>Newest</Link>
          </Button>
        )}
        {nextBefore && (
          <Button asChild variant="outline" size="sm">
            <Link href={`${base}/history?before=${encodeURIComponent(nextBefore)}`}>
              Older changes
            </Link>
          </Button>
        )}
      </div>
    </div>
  );
}
