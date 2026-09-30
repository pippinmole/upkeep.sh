import { BellRing, RotateCw, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Fragment, type ReactNode } from "react";

import { OsLogo } from "@/components/brand";
import { PageHeader } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { hostAlertsHref } from "@/lib/alerts-table";
import { collectorLabel, osLabel, requireHost } from "@/lib/host-page";
import { getHostFiringAlerts } from "@/lib/queries-alerts";
import { getHostSystem } from "@/lib/queries-host-facts";
import { getHostCollectors } from "@/lib/queries-remote";
import { getHostVulnSummary } from "@/lib/queries-vulns";
import { formatDateTime, relativeTime } from "@/lib/time";

import { CollectedBy } from "./collected-by";
import { CollectorFailures } from "./collector-failures";
import { HostTabs } from "./host-tabs";
import { RestartBadge, systemMeta } from "./system-badges";

export default async function HostLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ hostId: string }>;
}) {
  const { hostId } = await params;
  const { workspaceId, host } = await requireHost(hostId);
  const [vulns, sys, collectors, firing] = await Promise.all([
    getHostVulnSummary(workspaceId, host.id),
    getHostSystem(workspaceId, host.id),
    getHostCollectors(workspaceId, host.id),
    getHostFiringAlerts(workspaceId, host.id),
  ]);
  const snap = host.latestSnapshot;
  const base = `/dashboard/hosts/${host.id}`;
  const os = osLabel(snap);
  const packages = host.inventory.reduce((n, inv) => n + inv.openPackages, 0);

  // Surface every collector that didn't report ok in the latest push:
  // `error` means that section is unknown (not empty); `skipped` means not
  // applicable. Only errors get the warning treatment.
  const statuses = Object.entries(snap?.collectorStatus ?? {});
  const errors = statuses.filter(([, s]) => s.status === "error");
  const skipped = statuses.filter(([, s]) => s.status === "skipped");

  const meta: ReactNode[] = [];
  if (os) meta.push(<span key="os">{os}</span>);
  if (snap) {
    meta.push(
      host.runningKernel ? (
        <span
          key="kernel"
          className="font-mono"
          title="Running kernel (uname -r) from the latest snapshot"
        >
          {host.runningKernel}
        </span>
      ) : (
        <span
          key="kernel"
          className="underline decoration-dashed underline-offset-4"
          title="The agent didn't report the running kernel (older agent, or the collector failed). Kernel vulnerabilities are raised for every installed kernel until it does."
        >
          Running kernel unknown
        </span>
      ),
    );
  }
  meta.push(...systemMeta(sys));
  if (collectors.length > 0) meta.push(<CollectedBy key="collected" agents={collectors} />);
  meta.push(
    <span key="seen">
      Last seen{" "}
      <span
        title={
          snap
            ? `${formatDateTime(host.lastSeenAt)} · last snapshot ${formatDateTime(snap.collectedAt)}`
            : formatDateTime(host.lastSeenAt)
        }
      >
        {relativeTime(host.lastSeenAt)}
      </span>
    </span>,
  );

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <PageHeader
        breadcrumbs={[
          { label: "Hosts", href: "/dashboard/hosts" },
          { label: host.label ?? host.hostname },
        ]}
        title={host.label ?? host.hostname}
        // Wrapped so PageHeader's default icon sizing leaves the logo at 28px.
        icon={
          <span className="flex">
            <OsLogo osId={snap?.osId} size={28} colored />
          </span>
        }
        badges={
          <>
            {host.label && <span className="text-muted-foreground text-sm">{host.hostname}</span>}
            {firing > 0 && (
              <Link href={hostAlertsHref(host.id)} title="Alerts firing on this host">
                <Badge variant="warning">
                  <BellRing aria-hidden />
                  {firing} {firing === 1 ? "alert" : "alerts"} firing
                </Badge>
              </Link>
            )}
            {snap?.rebootRequired && (
              <Badge
                variant="warning"
                title={
                  snap.rebootPackages.length
                    ? `Requested by: ${snap.rebootPackages.join(", ")}`
                    : undefined
                }
              >
                <RotateCw aria-hidden />
                Reboot required
              </Badge>
            )}
            <RestartBadge sys={sys} hostId={host.id} />
            {vulns.open > 0 ? (
              <Link
                href={`${base}/vulnerabilities`}
                className="inline-flex items-center gap-1.5"
                title={`${vulns.open} open vulnerabilities; most severe: ${vulns.topSeverity}`}
              >
                {vulns.topSeverity && <SeverityBadge severity={vulns.topSeverity} />}
                {vulns.kev > 0 && <KevBadge count={vulns.kev} />}
              </Link>
            ) : (
              host.inventory.length > 0 && (
                <Badge variant="success">
                  <ShieldCheck aria-hidden />
                  No open vulnerabilities
                </Badge>
              )
            )}
          </>
        }
        meta={<MetaLine items={meta} />}
      />

      <CollectorFailures errors={errors} />
      {skipped.length > 0 && (
        <p className="text-muted-foreground text-xs">
          Not collected on this host:{" "}
          {skipped
            .map(([name, s]) => `${collectorLabel(name)}${s.reason ? ` (${s.reason})` : ""}`)
            .join(", ")}
        </p>
      )}

      <HostTabs
        hostId={host.id}
        openVulns={vulns.open}
        packages={host.inventory.length > 0 ? packages : null}
      />
      <div className="min-h-0 flex-1">{children}</div>
    </main>
  );
}

// Meta facts separated by a muted middle dot.
function MetaLine({ items }: { items: ReactNode[] }) {
  return (
    <>
      {items.map((item, i) => (
        <Fragment key={i}>
          {i > 0 && (
            <span aria-hidden className="text-muted-foreground/60 -mx-1.5">
              ·
            </span>
          )}
          {item}
        </Fragment>
      ))}
    </>
  );
}
