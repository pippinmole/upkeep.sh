import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { OsLogo } from "@/components/brand";
import { PageHeader, SectionHeading } from "@/components/layout/page-header";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FixCell, KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { AdvisoryList, CveFacts } from "@/components/vuln/cve-facts";
import { AdvisoryLinks } from "@/components/vuln/links";
import { auth } from "@/lib/auth";
import { osName } from "@/lib/os";
import { getFleetVulnDetail, type VulnHostRow } from "@/lib/queries-vulns";
import { isVulnKey } from "@/lib/severity";
import { formatDate, formatDateTime } from "@/lib/time";

type Params = Promise<{ vulnKey: string }>;

// Route params arrive percent-decoded. Anything that isn't a plausible
// CVE / advisory id is a 404 before it reaches SQL.
async function vulnKeyParam(params: Params): Promise<string> {
  const k = (await params).vulnKey;
  if (!isVulnKey(k)) notFound();
  return k;
}

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  return { title: `${await vulnKeyParam(params)} · Vulnerabilities` };
}

function hostName(r: { hostname: string; label: string | null }) {
  return r.label ? `${r.label} (${r.hostname})` : r.hostname;
}

// "ubuntu noble" with the distro's mark.
function Release({ distro, release }: { distro: string; release: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
      <OsLogo osId={distro} size={14} className="text-muted-foreground" />
      {osName(distro)} {release}
    </span>
  );
}

function HostsTable({ rows, resolved }: { rows: VulnHostRow[]; resolved: boolean }) {
  return (
    <div className="bg-card rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Host</TableHead>
            <TableHead>Package</TableHead>
            <TableHead>{resolved ? "Was installed" : "Installed"}</TableHead>
            <TableHead>Fixed in</TableHead>
            <TableHead>Severity</TableHead>
            <TableHead>{resolved ? "Resolved" : "Since"}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={`${r.hostId}:${r.sourcePackage}`}>
              <TableCell className="align-top">
                <span className="inline-flex items-center gap-2">
                  <OsLogo osId={r.osId} className="text-muted-foreground" />
                  <Link
                    href={`/dashboard/hosts/${r.hostId}/vulnerabilities?v=${encodeURIComponent(r.vulnKey)}${resolved ? "&status=resolved" : ""}`}
                    className="font-medium hover:underline"
                  >
                    {hostName(r)}
                  </Link>
                </span>
              </TableCell>
              <TableCell className="align-top">
                <div className="flex flex-col">
                  <span className="font-medium">{r.sourcePackage ?? "—"}</span>
                  <span
                    className="text-muted-foreground line-clamp-2 max-w-56 text-xs whitespace-normal"
                    title={r.packages.join(", ")}
                  >
                    {r.packages.join(", ")}
                  </span>
                  {r.runningKernelUnknown && (
                    <span className="text-muted-foreground text-xs">running kernel unknown</span>
                  )}
                </div>
              </TableCell>
              <TableCell className="align-top font-mono text-xs">
                {r.installedVersion ?? "—"}
              </TableCell>
              <TableCell className="align-top">
                <FixCell fixedVersion={r.fixedVersion} fixChannel={r.fixChannel} />
              </TableCell>
              <TableCell className="align-top">
                <div className="flex flex-wrap gap-1">
                  <SeverityBadge severity={r.severity} />
                  {r.isKev && <KevBadge />}
                </div>
              </TableCell>
              <TableCell className="text-muted-foreground align-top whitespace-nowrap">
                {resolved && r.resolvedAt ? (
                  <span title={formatDateTime(r.resolvedAt)}>{formatDate(r.resolvedAt)}</span>
                ) : (
                  <span title={formatDateTime(r.firstSeenAt)}>{formatDate(r.firstSeenAt)}</span>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

export default async function FleetVulnerabilityPage({ params }: { params: Params }) {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const vulnKey = await vulnKeyParam(params);

  const d = await getFleetVulnDetail(session.user.id, vulnKey);
  if (!d) notFound();

  const affectedHosts = new Set(d.affected.map((r) => r.hostId)).size;
  const previousHosts = new Set(d.previous.map((r) => r.hostId)).size;
  const top = d.affected[0] ?? d.previous[0];

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        breadcrumbs={[
          { label: "Vulnerabilities", href: "/dashboard/vulnerabilities" },
          { label: vulnKey },
        ]}
        title={vulnKey}
        badges={
          <>
            {top && <SeverityBadge severity={top.severity} />}
            {(d.cve?.isKev || top?.isKev) && <KevBadge />}
          </>
        }
        meta={
          <>
            <span>
              {affectedHosts > 0
                ? `Affects ${affectedHosts} of your hosts now`
                : "Not affecting any of your hosts now"}
              {previousHosts > 0 && ` · previously affected ${previousHosts}`}
            </span>
            <AdvisoryLinks ids={[vulnKey]} className="inline-flex text-sm" />
          </>
        }
      />

      <section className="bg-card flex flex-col gap-3 rounded-lg border p-4">
        <SectionHeading>Details</SectionHeading>
        <CveFacts cve={d.cve} />
      </section>

      <section className="flex flex-col gap-2">
        <SectionHeading>Affected hosts</SectionHeading>
        {d.affected.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            None of your hosts has an open finding for {vulnKey}.
          </p>
        ) : (
          <HostsTable rows={d.affected} resolved={false} />
        )}
      </section>

      <section className="flex flex-col gap-2">
        <SectionHeading description="Package versions currently installed on your hosts that match this vulnerability. Kernel packages that aren't the running kernel appear here without a finding.">
          Affected versions installed on your hosts
        </SectionHeading>
        {d.versions.length === 0 ? (
          <p className="text-muted-foreground text-sm">None.</p>
        ) : (
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Package</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Release</TableHead>
                  <TableHead>Fixed in</TableHead>
                  <TableHead className="text-right">Hosts</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.versions.map((v) => (
                  <TableRow key={`${v.distro}:${v.release}:${v.name}:${v.version}:${v.arch}`}>
                    <TableCell>
                      <Link
                        href={`/dashboard/packages/${encodeURIComponent(v.name)}`}
                        className="font-medium hover:underline"
                      >
                        {v.name}
                      </Link>
                      {v.arch && <span className="text-muted-foreground text-xs"> {v.arch}</span>}
                      {v.isKernel && (
                        <Badge variant="neutral" className="ml-2 font-normal">
                          kernel
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{v.version}</TableCell>
                    <TableCell className="text-muted-foreground">
                      <Release distro={v.distro} release={v.release} />
                    </TableCell>
                    <TableCell>
                      <FixCell fixedVersion={v.fixedVersion} fixChannel={v.fixChannel} />
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{v.hosts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </section>

      {d.previous.length > 0 && (
        <section className="flex flex-col gap-2">
          <SectionHeading description="Hosts whose finding was resolved, usually by upgrading the package.">
            Previously affected
          </SectionHeading>
          <HostsTable rows={d.previous} resolved />
        </section>
      )}

      <section className="flex flex-col gap-2">
        <SectionHeading>Fixed versions by release</SectionHeading>
        {d.releaseFixes.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            No per-release data for the supported releases.
          </p>
        ) : (
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Release</TableHead>
                  <TableHead>Source package</TableHead>
                  <TableHead>Fixed in</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Advisories</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {d.releaseFixes.map((f) => (
                  <TableRow
                    key={`${f.distro}:${f.release}:${f.sourcePackage}:${f.channel}:${f.status}:${f.fixedVersion}`}
                  >
                    <TableCell>
                      <Release distro={f.distro} release={f.release} />
                    </TableCell>
                    <TableCell>{f.sourcePackage}</TableCell>
                    <TableCell>
                      <FixCell
                        fixedVersion={f.fixedVersion}
                        fixChannel={f.fixedVersion ? f.channel : null}
                      />
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {f.distroSeverity ?? "—"}
                    </TableCell>
                    <TableCell>
                      <AdvisoryLinks ids={f.advisoryIds} />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
        {d.releaseFixesTruncated && (
          <p className="text-muted-foreground text-xs">Showing the first 200 rows.</p>
        )}
      </section>

      <section className="flex flex-col gap-2">
        <SectionHeading>Advisories</SectionHeading>
        <AdvisoryList advisories={d.advisories} />
      </section>
    </main>
  );
}
