import { Bug, Flame, SearchX, TriangleAlert } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { PageHeader } from "@/components/layout/page-header";
import {
  CardTitle as ScopedTitle,
  MetricCard,
  plural,
  SeverityBars,
} from "@/components/overview/cards";
import { EstateCard } from "@/components/overview/estate-card";
import { FirstRunHero, WaitingForFirstReport } from "@/components/overview/first-run";
import { GettingStarted } from "@/components/overview/getting-started";
import { ContainerImagesSection } from "@/components/overview/image-section";
import { LatestReportCard } from "@/components/overview/latest-report";
import { attentionItems, NeedsAttention } from "@/components/overview/needs-attention";
import { UrgentVulns } from "@/components/overview/urgent-vulns";
import { Card, CardContent, CardHeader } from "@/components/ui/card";
import { auth } from "@/lib/auth";
import { getOnboardingState } from "@/lib/queries-onboarding";
import { getEstateHealth, getLatestReport } from "@/lib/queries-overview";
import { getImageOverviewStats, getUrgentVulns } from "@/lib/queries-overview-images";
import { getCollectorAgents } from "@/lib/queries-remote";
import { getOverviewStats } from "@/lib/queries-vulns";

import { AddHostDialog } from "./hosts/add-host-dialog";

export const metadata: Metadata = {
  title: "Overview",
};

const VULNS = "/dashboard/vulnerabilities";

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;

  // Host package and container image numbers are fetched and shown
  // separately, never summed: they are fixed differently (DOMAIN_MODEL.md
  // §3.6 "Overview").
  const [onboarding, agents, estate, stats, images, urgent, report] = await Promise.all([
    getOnboardingState(userId),
    getCollectorAgents(userId),
    getEstateHealth(userId),
    getOverviewStats(userId),
    getImageOverviewStats(userId),
    getUrgentVulns(userId),
    getLatestReport(userId),
  ]);
  const serverUrl = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
  const v = stats.vulns;

  const firstRun = !onboarding.agent && estate.hosts.length === 0;
  const header = (
    <PageHeader
      title="Overview"
      description="Estate health and what needs attention now."
      // The first-run hero carries its own Add host button.
      actions={firstRun ? undefined : <AddHostDialog serverUrl={serverUrl} agents={agents} />}
    />
  );

  // Nothing has reported yet: a hero (or a waiting state) instead of zeros.
  if (!onboarding.hostReported) {
    const waitingOn = [
      ...estate.signals.neverConnected,
      ...estate.hosts.filter((h) => !h.reported).map((h) => h.name),
    ];
    return (
      <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
        {header}
        {firstRun ? (
          <FirstRunHero serverUrl={serverUrl} agents={agents} />
        ) : (
          <WaitingForFirstReport names={waitingOn} />
        )}
      </main>
    );
  }

  const critHigh = v.bySeverity.critical + v.bySeverity.high;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      {header}

      <GettingStarted state={onboarding} />

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <NeedsAttention
          className="md:col-span-2"
          items={attentionItems(estate, { findings: v.kev, hosts: stats.hostsWithKev })}
        />
        <EstateCard className="md:col-span-2 lg:col-span-1" estate={estate} />
      </div>

      <section aria-labelledby="host-vulns" className="flex flex-col gap-3">
        <h2 id="host-vulns" className="sr-only">
          Host package vulnerabilities
        </h2>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <MetricCard
            title="Open vulnerabilities"
            value={v.open}
            tone="neutral"
            icon={<Bug />}
            href={VULNS}
          >
            {plural(stats.distinctOpenVulns, "distinct vulnerability", "distinct vulnerabilities")}{" "}
            on {plural(stats.hostsWithOpen, "host", "hosts")}
          </MetricCard>
          <MetricCard
            title="Known exploited (KEV)"
            value={v.kev}
            tone="kev"
            icon={<Flame />}
            href={v.kev > 0 ? `${VULNS}?kev=1` : undefined}
          >
            {v.kev > 0
              ? `On ${plural(stats.hostsWithKev, "host", "hosts")}: patch these first`
              : "None in host packages"}
          </MetricCard>
          <MetricCard
            title="Critical + High"
            value={critHigh}
            tone="critical"
            icon={<TriangleAlert />}
            href={
              v.bySeverity.critical > 0
                ? `${VULNS}?severity=critical`
                : critHigh > 0
                  ? `${VULNS}?severity=high`
                  : undefined
            }
          >
            <span className="tabular-nums">{v.bySeverity.critical}</span> critical ·{" "}
            <span className="tabular-nums">{v.bySeverity.high}</span> high
          </MetricCard>
          <MetricCard
            title="No fix yet"
            value={v.unfixed}
            tone="neutral"
            icon={<SearchX />}
            href={v.unfixed > 0 ? `${VULNS}?fix=none` : undefined}
          >
            No fixed version published yet
          </MetricCard>
        </div>
        <p className="text-muted-foreground text-xs">
          Host packages only: container images are counted separately below.
        </p>
      </section>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <UrgentVulns className="md:col-span-2" rows={urgent} />
        <HostSeverityCard stats={stats} className="md:col-span-2 lg:col-span-1" />
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        <ContainerImagesSection className="md:col-span-2" stats={images} />
        <LatestReportCard className="md:col-span-2 lg:col-span-1" report={report} />
      </div>
    </main>
  );
}

// Host package findings by severity, and how they can be fixed. The Ubuntu
// Pro row only appears when some finding needs it.
function HostSeverityCard({
  stats,
  className,
}: {
  stats: Awaited<ReturnType<typeof getOverviewStats>>;
  className?: string;
}) {
  const v = stats.vulns;
  const fixRows = [
    {
      href: `${VULNS}?fix=available`,
      label: "Fix available",
      help: "An upgrade from the standard archive fixes it",
      value: v.fixable,
    },
    ...(v.proOnly > 0
      ? [
          {
            href: `${VULNS}?fix=pro`,
            label: "Fix requires Ubuntu Pro",
            help: "Only fixed in ESM / Ubuntu Pro",
            value: v.proOnly,
          },
        ]
      : []),
    {
      href: `${VULNS}?fix=none`,
      label: "No fix yet",
      help: "No fixed version published for the release",
      value: v.unfixed,
    },
  ];
  return (
    <Card className={className}>
      <CardHeader>
        <ScopedTitle scope="Host packages">Open findings by severity</ScopedTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        {v.open === 0 ? (
          <p className="text-muted-foreground text-sm">No open host package findings.</p>
        ) : (
          <>
            <SeverityBars
              counts={v.bySeverity}
              total={v.open}
              href={(s) => `${VULNS}?severity=${s}`}
            />
            <div className="flex flex-col gap-2 border-t pt-4">
              <h3 className="text-sm font-semibold">Fix availability</h3>
              <dl className="grid grid-cols-[1fr_auto] gap-x-4 gap-y-2 text-sm">
                {fixRows.map((r) => (
                  <div key={r.href} className="contents">
                    <dt>
                      <Link href={r.href} className="hover:underline">
                        {r.label}
                      </Link>
                      <span className="text-muted-foreground block text-xs">{r.help}</span>
                    </dt>
                    <dd className="text-right text-lg font-semibold tabular-nums">{r.value}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
