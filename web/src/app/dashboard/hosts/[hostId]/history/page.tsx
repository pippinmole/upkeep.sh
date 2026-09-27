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
import { compareDebVersions } from "@/lib/debversion";
import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostHistory, type RangeEvent } from "@/lib/queries-inventory";
import { type ChangeEffect, getChangeEffects } from "@/lib/queries-vulns";
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
  // boundary. Direction needs ecosystem version semantics: deb uses the
  // dpkg ordering port in lib/debversion.ts (checked against the Go
  // debversion package's dpkg vectors); other ecosystems, and versions
  // dpkg rejects, stay "changed".
  | {
      kind: "upgraded" | "downgraded" | "changed";
      from: RangeEvent;
      to: RangeEvent;
    };

type PairKind = "upgraded" | "downgraded" | "changed";

function direction(from: RangeEvent, to: RangeEvent): PairKind {
  if (from.ecosystem !== "deb") return "changed";
  const c = compareDebVersions(from.version, to.version);
  return c === -1 ? "upgraded" : c === 1 ? "downgraded" : "changed";
}

const isPair = (c: Change): c is Extract<Change, { from: RangeEvent }> => "from" in c;
const pairKey = (from: RangeEvent, to: RangeEvent) => `${from.softwareId}>${to.softwareId}`;

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
      const from = g.closes[0];
      const to = g.opens[0];
      out.push({ kind: direction(from, to), from, to });
    } else {
      for (const e of g.closes) out.push({ kind: "removed", e });
      for (const e of g.opens) out.push({ kind: "installed", e });
    }
  }
  const name = (c: Change) => (isPair(c) ? c.to : c.e);
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
  upgraded: {
    label: "Upgraded",
    className: "border-sky-500/40 text-sky-700 dark:text-sky-400",
  },
  downgraded: {
    label: "Downgraded",
    className: "border-amber-500/50 text-amber-700 dark:text-amber-400",
  },
  changed: {
    label: "Changed",
    className: "border-sky-500/40 text-sky-700 dark:text-sky-400",
  },
};

// "Fixed 3 CVEs (1 KEV)" / "Introduced 1": set difference of today's
// matches (software_vulnerabilities) between the two versions.
function EffectCell({ effect }: { effect: ChangeEffect | undefined }) {
  if (!effect || (effect.fixed === 0 && effect.introduced === 0)) {
    return <span className="text-muted-foreground">—</span>;
  }
  return (
    <div className="flex flex-col text-xs">
      {effect.fixed > 0 && (
        <span className="text-emerald-700 dark:text-emerald-400">
          Fixed {effect.fixed} {effect.fixed === 1 ? "vulnerability" : "vulnerabilities"}
          {effect.fixedKev > 0 && <strong> ({effect.fixedKev} KEV)</strong>}
        </span>
      )}
      {effect.introduced > 0 && (
        <span className="text-red-700 dark:text-red-400">
          Introduced {effect.introduced}{" "}
          {effect.introduced === 1 ? "vulnerability" : "vulnerabilities"}
        </span>
      )}
    </div>
  );
}

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

  // Pair every boundary's changes up front so the security effect of all
  // version changes on this page is one query.
  const perBoundary = boundaries.map((b) => {
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
    return { b, baselineCount, changes: pairChanges(rest) };
  });
  const pairs = perBoundary.flatMap((x) =>
    x.changes.filter(isPair).map((c) => ({ from: c.from.softwareId, to: c.to.softwareId })),
  );
  const effects = await getChangeEffects(userId, host.id, pairs);

  const days = boundaries.map((b) => formatDate(b.at));
  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground text-sm">
        Package changes per applied inventory, newest first. Times are the snapshot&apos;s
        collection time. Security effect compares the two versions against today&apos;s advisory
        data, not what was known at the time.
      </p>
      {perBoundary.map(({ b, baselineCount, changes }, i) => {
        const counts = {
          installed: 0,
          removed: 0,
          upgraded: 0,
          downgraded: 0,
          changed: 0,
        };
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
                      counts.upgraded && `${counts.upgraded} upgraded`,
                      counts.downgraded && `${counts.downgraded} downgraded`,
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
                      <TableHead>Security effect</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {changes.map((c) => {
                      const e = isPair(c) ? c.to : c.e;
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
                            {isPair(c) ? (
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
                          <TableCell>
                            {isPair(c) ? (
                              <EffectCell effect={effects.get(pairKey(c.from, c.to))} />
                            ) : (
                              <span className="text-muted-foreground">—</span>
                            )}
                          </TableCell>
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
