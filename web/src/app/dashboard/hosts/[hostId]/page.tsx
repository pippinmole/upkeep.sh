import type { Metadata } from "next";
import Link from "next/link";

import { SeverityBars } from "@/components/overview/cards";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostDockerCounts } from "@/lib/queries-docker";
import { getHostListeners } from "@/lib/queries-host-facts";
import { getHostFindings, getHostVulnSummary } from "@/lib/queries-vulns";
import { formatDateTime, relativeTime } from "@/lib/time";

import { Muted, OverviewCard } from "./overview-card";
import { SystemOverview } from "./system-overview";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: hostTitle(host) };
}

const TOP_FINDINGS = 5;

// Host overview: what needs attention on this host (vulnerabilities by
// severity, the most urgent open findings, what listens on every
// interface) and its inventory and system facts, each linking to its tab.
export default async function HostOverviewPage({ params }: { params: Params }) {
  const { workspaceId, host } = await requireHost((await params).hostId);
  const snap = host.latestSnapshot;
  const base = `/dashboard/hosts/${host.id}`;

  const [vulns, top, listeners, docker] = await Promise.all([
    getHostVulnSummary(workspaceId, host.id),
    getHostFindings(workspaceId, host.id, {
      status: "open",
      q: null,
      severity: null,
      kev: false,
      fix: null,
      sort: "severity",
      page: 1,
      pageSize: TOP_FINDINGS,
    }),
    getHostListeners(workspaceId, host.id),
    getHostDockerCounts(workspaceId, host.id),
  ]);
  const wildcard = listeners.rows.filter((l) => l.wildcard);
  const listenersReported = listeners.freshness.tcp !== null || listeners.freshness.udp !== null;
  const hasDocker = docker.containers > 0 || docker.images > 0;

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <OverviewCard
        title="Vulnerabilities"
        href={`${base}/vulnerabilities`}
        linkLabel={vulns.open > 0 ? `All ${vulns.open}` : "View"}
      >
        {host.inventory.length === 0 ? (
          <Muted>Matched once the agent reports a package inventory.</Muted>
        ) : vulns.open === 0 ? (
          <Muted>No open vulnerabilities.</Muted>
        ) : (
          <>
            <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
              <span>
                <span className="font-semibold tabular-nums">{vulns.open}</span> open
              </span>
              {vulns.kev > 0 && <KevBadge count={vulns.kev} />}
              <span className="text-muted-foreground">
                {vulns.fixable} fixable · {vulns.unfixed} no fix yet
              </span>
            </p>
            <SeverityBars
              counts={vulns.bySeverity}
              total={vulns.open}
              href={(s) => `${base}/vulnerabilities?severity=${s}`}
            />
          </>
        )}
      </OverviewCard>

      <OverviewCard
        title="Most urgent"
        href={`${base}/vulnerabilities`}
        linkLabel="Vulnerabilities"
      >
        {top.rows.length === 0 ? (
          <Muted>Nothing open.</Muted>
        ) : (
          <ul className="flex flex-col divide-y text-sm">
            {top.rows.map((f) => (
              <li
                key={`${f.sourcePackage}:${f.vulnKey}`}
                className="flex items-center gap-2 py-2 first:pt-0 last:pb-0"
              >
                <SeverityBadge severity={f.severity} />
                {f.isKev && <KevBadge />}
                <Link
                  href={`${base}/vulnerabilities?v=${encodeURIComponent(f.vulnKey)}`}
                  className="font-medium hover:underline"
                >
                  {f.vulnKey}
                </Link>
                <span
                  className="text-muted-foreground ml-auto truncate font-mono text-xs"
                  title={f.sourcePackage ?? undefined}
                >
                  {f.sourcePackage}
                </span>
              </li>
            ))}
          </ul>
        )}
      </OverviewCard>

      <OverviewCard title="Exposure" href={`${base}/listeners`} linkLabel="Listeners">
        {!listenersReported ? (
          <Muted>Listening ports haven&apos;t been reported for this host.</Muted>
        ) : (
          <div className="flex flex-col gap-2 text-sm">
            <p>
              <span className="font-semibold tabular-nums">{wildcard.length}</span>{" "}
              {wildcard.length === 1 ? "port listens" : "ports listen"} on all interfaces
              <span className="text-muted-foreground">
                {" "}
                · {listeners.rows.length} listening in total
              </span>
            </p>
            {wildcard.length > 0 && (
              <p className="text-muted-foreground flex flex-wrap gap-x-2 gap-y-1 font-mono text-xs">
                {wildcard.slice(0, 12).map((l) => (
                  <span key={l.key} title={l.processName ?? undefined}>
                    {l.port}/{l.proto}
                  </span>
                ))}
                {wildcard.length > 12 && <span>…</span>}
              </p>
            )}
            <p className="text-muted-foreground text-xs">
              Reachability also depends on the host&apos;s firewall, which isn&apos;t collected.
            </p>
          </div>
        )}
        {hasDocker && (
          <p className="mt-3 flex flex-wrap gap-x-3 text-sm">
            <Link href={`${base}/containers`} className="hover:underline">
              <span className="font-semibold tabular-nums">{docker.containers}</span>{" "}
              {docker.containers === 1 ? "container" : "containers"}
              <span className="text-muted-foreground"> ({docker.running} running)</span>
            </Link>
            <Link href={`${base}/images`} className="hover:underline">
              <span className="font-semibold tabular-nums">{docker.images}</span>{" "}
              {docker.images === 1 ? "image" : "images"}
            </Link>
          </p>
        )}
      </OverviewCard>

      <OverviewCard title="Package inventory" href={`${base}/packages`} linkLabel="Packages">
        {host.inventory.length === 0 ? (
          <Muted>No package inventory has been recorded for this host yet.</Muted>
        ) : (
          <dl className="space-y-3 text-sm">
            {host.inventory.map((inv) => (
              <div key={inv.ecosystem}>
                <dt className="font-medium">
                  <Link
                    href={`${base}/packages?ecosystem=${encodeURIComponent(inv.ecosystem)}`}
                    className="hover:underline"
                  >
                    <span className="tabular-nums">{inv.openPackages.toLocaleString("en-GB")}</span>{" "}
                    {inv.ecosystem} packages
                  </Link>
                </dt>
                <dd className="text-muted-foreground">
                  Confirmed{" "}
                  <span title={formatDateTime(inv.confirmedAt)}>
                    {relativeTime(inv.confirmedAt)}
                  </span>{" "}
                  · last changed{" "}
                  <Link href={`${base}/history`} className="hover:underline">
                    <span title={formatDateTime(inv.changedAt)}>{relativeTime(inv.changedAt)}</span>
                  </Link>
                </dd>
              </div>
            ))}
          </dl>
        )}
        <div className="mt-4 border-t pt-3 text-sm">
          <p className="font-medium">Reboot</p>
          {!snap ? (
            <Muted>No snapshots yet.</Muted>
          ) : snap.rebootRequired ? (
            <p className="text-warning-fg">
              A reboot is required
              {snap.rebootPackages.length > 0 && (
                <>
                  {" "}
                  (requested by{" "}
                  <span className="font-mono text-xs">{snap.rebootPackages.join(", ")}</span>)
                </>
              )}
              .
            </p>
          ) : (
            <Muted>No reboot pending.</Muted>
          )}
          <p className="text-muted-foreground mt-2 text-xs">
            Registered {formatDateTime(host.createdAt)}
          </p>
        </div>
      </OverviewCard>

      <SystemOverview workspaceId={workspaceId} hostId={host.id} />
    </div>
  );
}
