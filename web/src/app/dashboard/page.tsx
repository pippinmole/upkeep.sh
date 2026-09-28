import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { CardTitle, plural, SeverityBars, StatCard } from "@/components/overview/cards";
import { ContainerImagesSection } from "@/components/overview/image-section";
import { UrgentVulns } from "@/components/overview/urgent-vulns";
import { auth } from "@/lib/auth";
import { getImageOverviewStats, getUrgentVulns } from "@/lib/queries-overview-images";
import { getOverviewStats } from "@/lib/queries-vulns";

export const metadata: Metadata = {
  title: "Dashboard",
};

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;

  // Host package and container image numbers are fetched and shown
  // separately, never summed: they are fixed differently (DOMAIN_MODEL.md
  // §3.6 "Overview").
  const [stats, images, urgent] = await Promise.all([
    getOverviewStats(userId),
    getImageOverviewStats(userId),
    getUrgentVulns(userId),
  ]);
  const v = stats.vulns;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Overview</h1>
        <p className="text-muted-foreground text-sm">
          Fleet health across your hosts and their container images.
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Hosts" value={stats.hosts} href="/dashboard/hosts">
          {stats.hosts === 0
            ? "Register an agent to get started"
            : stats.staleHosts > 0
              ? `${stats.staleHosts} not seen in 24h`
              : "All reported in the last 24h"}
        </StatCard>
        <StatCard
          title="Host package vulnerabilities"
          value={v.open}
          href="/dashboard/vulnerabilities"
        >
          {plural(stats.distinctOpenVulns, "distinct vulnerability", "distinct vulnerabilities")} on{" "}
          {plural(stats.hostsWithOpen, "host", "hosts")}
        </StatCard>
        <StatCard
          title="Known exploited in host packages"
          value={v.kev}
          href={v.kev > 0 ? "/dashboard/vulnerabilities?kev=1" : undefined}
        >
          {v.kev > 0
            ? `On ${plural(stats.hostsWithKev, "host", "hosts")}: patch these first`
            : "No known-exploited vulnerabilities"}
        </StatCard>
        <StatCard title="Reboot pending" value={stats.rebootPending}>
          {stats.rebootPending > 0
            ? "Hosts whose latest snapshot asks for a reboot"
            : "No host is waiting for a reboot"}
        </StatCard>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <section className="bg-card rounded-lg border p-4">
          <CardTitle scope="Host packages">Open findings by severity</CardTitle>
          {v.open === 0 ? (
            <p className="text-muted-foreground mt-2 text-sm">No open host package findings.</p>
          ) : (
            <SeverityBars
              counts={v.bySeverity}
              total={v.open}
              href={(s) => `/dashboard/vulnerabilities?severity=${s}`}
            />
          )}
        </section>

        <section className="bg-card rounded-lg border p-4">
          <CardTitle scope="Host packages">Fix availability</CardTitle>
          {v.open === 0 ? (
            <p className="text-muted-foreground mt-2 text-sm">No open host package findings.</p>
          ) : (
            <dl className="mt-3 grid grid-cols-[1fr_auto] gap-x-4 gap-y-2 text-sm">
              <dt>
                <Link href="/dashboard/vulnerabilities?fix=available" className="hover:underline">
                  Fix available
                </Link>
                <span className="text-muted-foreground block text-xs">
                  An upgrade from the standard archive fixes it
                </span>
              </dt>
              <dd className="text-right text-lg font-semibold tabular-nums">{v.fixable}</dd>
              <dt>
                <Link href="/dashboard/vulnerabilities?fix=pro" className="hover:underline">
                  Fix requires Ubuntu Pro
                </Link>
                <span className="text-muted-foreground block text-xs">
                  Only fixed in ESM / Ubuntu Pro
                </span>
              </dt>
              <dd className="text-right text-lg font-semibold tabular-nums">{v.proOnly}</dd>
              <dt>
                <Link href="/dashboard/vulnerabilities?fix=none" className="hover:underline">
                  No fix yet
                </Link>
                <span className="text-muted-foreground block text-xs">
                  No fixed version published for the release
                </span>
              </dt>
              <dd className="text-right text-lg font-semibold tabular-nums">{v.unfixed}</dd>
            </dl>
          )}
        </section>
      </div>

      <ContainerImagesSection stats={images} />

      <UrgentVulns rows={urgent} />
    </main>
  );
}
