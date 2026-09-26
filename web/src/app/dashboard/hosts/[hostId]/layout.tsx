import { AlertTriangle, ArrowLeft, Cpu, RotateCw, ShieldAlert, ShieldCheck } from "lucide-react";
import Link from "next/link";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { collectorLabel, hostTitle, osLabel, requireHost } from "@/lib/host-page";
import { getHostVulnSummary } from "@/lib/queries-vulns";
import { formatDateTime, relativeTime } from "@/lib/time";

import { HostTabs } from "./host-tabs";

export default async function HostLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ hostId: string }>;
}) {
  const { hostId } = await params;
  const { userId, host } = await requireHost(hostId);
  const vulns = await getHostVulnSummary(userId, host.id);
  const snap = host.latestSnapshot;
  const vulnHref = `/dashboard/hosts/${host.id}/vulnerabilities`;
  const os = osLabel(snap);

  // Surface every collector that didn't report ok in the latest push:
  // `error` means that section is unknown (not empty); `skipped` means not
  // applicable. Only errors get the warning treatment.
  const statuses = Object.entries(snap?.collectorStatus ?? {});
  const errors = statuses.filter(([, s]) => s.status === "error");
  const skipped = statuses.filter(([, s]) => s.status === "skipped");
  // A failed package source makes the inventory tabs stale, so that one is
  // red; other collector failures are a softer warning.
  const packagesFailed = errors.some(([name]) => name.endsWith("_packages"));

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <div>
        <Link
          href="/dashboard/agents"
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm"
        >
          <ArrowLeft className="size-3.5" />
          All hosts
        </Link>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <h1 className="text-2xl font-bold">{hostTitle(host)}</h1>
          {os && <Badge variant="secondary">{os}</Badge>}
          {snap?.rebootRequired && (
            <Badge
              variant="outline"
              className="gap-1 border-amber-500/50 text-amber-700 dark:text-amber-400"
              title={
                snap.rebootPackages.length
                  ? `Requested by: ${snap.rebootPackages.join(", ")}`
                  : undefined
              }
            >
              <RotateCw className="size-3" />
              Reboot required
            </Badge>
          )}
          {vulns.open > 0 ? (
            <Link href={vulnHref} className="inline-flex items-center gap-1.5">
              <Badge
                variant="outline"
                className="gap-1"
                title={`${vulns.open} open vulnerabilities; most severe: ${vulns.topSeverity}`}
              >
                <ShieldAlert className="size-3" />
                {vulns.open} {vulns.open === 1 ? "vulnerability" : "vulnerabilities"}
              </Badge>
              {vulns.topSeverity && <SeverityBadge severity={vulns.topSeverity} />}
              {vulns.kev > 0 && <KevBadge count={vulns.kev} />}
            </Link>
          ) : (
            host.inventory.length > 0 && (
              <Badge variant="outline" className="text-muted-foreground gap-1 font-normal">
                <ShieldCheck className="size-3" />
                No open vulnerabilities
              </Badge>
            )
          )}
          {snap &&
            (host.runningKernel ? (
              <Badge
                variant="outline"
                className="text-muted-foreground gap-1 font-mono font-normal"
                title="Running kernel (uname -r) from the latest snapshot"
              >
                <Cpu className="size-3" />
                {host.runningKernel}
              </Badge>
            ) : (
              <Badge
                variant="outline"
                className="text-muted-foreground gap-1 border-dashed font-normal"
                title="The agent didn't report the running kernel (older agent, or the collector failed). Kernel vulnerabilities are raised for every installed kernel until it does."
              >
                <Cpu className="size-3" />
                Running kernel unknown
              </Badge>
            ))}
        </div>
        <p className="text-muted-foreground mt-1 text-sm">
          Last seen{" "}
          <span title={formatDateTime(host.lastSeenAt)}>{relativeTime(host.lastSeenAt)}</span>
          {snap && <> · last snapshot {formatDateTime(snap.collectedAt)}</>}
        </p>
      </div>

      {errors.length > 0 && (
        <Alert variant={packagesFailed ? "destructive" : "default"}>
          <AlertTriangle
            className={packagesFailed ? "size-4" : "size-4 text-amber-600! dark:text-amber-400!"}
          />
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

      <HostTabs hostId={host.id} openVulns={vulns.open} />
      <div className="min-h-0 flex-1">{children}</div>
    </main>
  );
}
