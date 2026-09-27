import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { vulnHref } from "@/components/vuln/links";
import { auth } from "@/lib/auth";
import { getFleetVulns, getOverviewStats } from "@/lib/queries-vulns";
import { SEVERITIES } from "@/lib/severity";

export const metadata: Metadata = {
  title: "Dashboard",
};

function StatCard({
  title,
  value,
  href,
  children,
}: {
  title: string;
  value: React.ReactNode;
  href?: string;
  children?: React.ReactNode;
}) {
  const body = (
    <>
      <p className="text-muted-foreground text-sm font-medium">{title}</p>
      <p className="mt-1 text-3xl font-semibold tabular-nums">{value}</p>
      {children && <div className="text-muted-foreground mt-2 text-sm">{children}</div>}
    </>
  );
  return href ? (
    <Link
      href={href}
      className="bg-card hover:bg-accent/50 rounded-lg border p-4 transition-colors"
    >
      {body}
    </Link>
  ) : (
    <div className="bg-card rounded-lg border p-4">{body}</div>
  );
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;

  const [stats, top] = await Promise.all([
    getOverviewStats(userId),
    getFleetVulns(userId, {
      status: "open",
      q: null,
      severity: null,
      kev: false,
      fix: null,
      sort: "severity",
      page: 1,
      pageSize: 5,
    }),
  ]);
  const v = stats.vulns;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Overview</h1>
        <p className="text-muted-foreground text-sm">Fleet health across your hosts.</p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Hosts" value={stats.hosts} href="/dashboard/hosts">
          {stats.hosts === 0
            ? "Register an agent to get started"
            : stats.staleHosts > 0
              ? `${stats.staleHosts} not seen in 24h`
              : "All reported in the last 24h"}
        </StatCard>
        <StatCard title="Open vulnerabilities" value={v.open} href="/dashboard/vulnerabilities">
          {plural(stats.distinctOpenVulns, "distinct vulnerability", "distinct vulnerabilities")} on{" "}
          {plural(stats.hostsWithOpen, "host", "hosts")}
        </StatCard>
        <StatCard
          title="Known exploited (KEV)"
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
          <h2 className="font-semibold">Open findings by severity</h2>
          {v.open === 0 ? (
            <p className="text-muted-foreground mt-2 text-sm">No open findings.</p>
          ) : (
            <ul className="mt-3 flex flex-col gap-2">
              {SEVERITIES.map((s) => (
                <li key={s} className="flex items-center gap-3">
                  <Link href={`/dashboard/vulnerabilities?severity=${s}`} className="w-24 shrink-0">
                    <SeverityBadge severity={s} />
                  </Link>
                  <div className="bg-muted h-2 flex-1 overflow-hidden rounded-full">
                    <div
                      className="bg-foreground/60 h-full rounded-full"
                      style={{ width: `${(v.bySeverity[s] / v.open) * 100}%` }}
                    />
                  </div>
                  <span className="w-12 text-right text-sm tabular-nums">{v.bySeverity[s]}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="bg-card rounded-lg border p-4">
          <h2 className="font-semibold">Fix availability</h2>
          {v.open === 0 ? (
            <p className="text-muted-foreground mt-2 text-sm">No open findings.</p>
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

      <section className="flex flex-col gap-2">
        <div className="flex items-baseline justify-between gap-2">
          <h2 className="font-semibold">Most urgent vulnerabilities</h2>
          <Link
            href="/dashboard/vulnerabilities"
            className="text-muted-foreground hover:text-foreground text-sm hover:underline"
          >
            View all
          </Link>
        </div>
        {top.rows.length === 0 ? (
          <p className="text-muted-foreground text-sm">Nothing open.</p>
        ) : (
          <ul className="bg-card divide-y rounded-lg border">
            {top.rows.map((r) => (
              <li
                key={r.vulnKey}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5"
              >
                <Link href={vulnHref(r.vulnKey)} className="font-medium hover:underline">
                  {r.vulnKey}
                </Link>
                <SeverityBadge severity={r.severity} />
                {r.isKev && <KevBadge />}
                <span className="text-muted-foreground text-sm">
                  {r.packages.join(", ")} · {plural(r.affectedHosts, "host", "hosts")}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}
