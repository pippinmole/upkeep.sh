import { AlertTriangle, RotateCw, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { Fragment, type ReactNode } from "react";

import { OsLogo } from "@/components/brand";
import { PageHeader } from "@/components/layout/page-header";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { collectorLabel, osLabel, requireHost } from "@/lib/host-page";
import { getHostSystem } from "@/lib/queries-host-facts";
import { getHostCollectors } from "@/lib/queries-remote";
import { getHostVulnSummary } from "@/lib/queries-vulns";
import { formatDateTime, relativeTime } from "@/lib/time";

import { CollectedBy } from "./collected-by";
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
  const { userId, host } = await requireHost(hostId);
  const [vulns, sys, collectors] = await Promise.all([
    getHostVulnSummary(userId, host.id),
    getHostSystem(userId, host.id),
    getHostCollectors(userId, host.id),
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
  // A failed package source makes the inventory tabs stale, so that one is
  // red; other collector failures are a softer warning.
  const packagesFailed = errors.some(([name]) => name.endsWith("_packages"));

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

      {errors.length > 0 && (
        <Alert variant={packagesFailed ? "destructive" : "default"}>
          <AlertTriangle className={packagesFailed ? "size-4" : "text-warning-fg! size-4"} />
          <AlertTitle>
            {errors.length === 1
              ? "A collector failed in the latest snapshot"
              : `${errors.length} collectors failed in the latest snapshot`}
          </AlertTitle>
          <AlertDescription>
            <ul className="mt-1 list-none space-y-0.5">
              {errors.map(([name, s]) => (
                <li key={name}>
                  <span className="font-medium">{collectorLabel(name)} failed</span>
                  {s.error ? `: ${s.error}` : ""}
                </li>
              ))}
            </ul>
            {packagesFailed && (
              <p className="mt-1">
                The package list below is the last successfully collected inventory, not an empty
                one.
              </p>
            )}
          </AlertDescription>
        </Alert>
      )}
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
