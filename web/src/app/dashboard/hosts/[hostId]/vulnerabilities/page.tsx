import { Cpu, Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { FilterBar } from "@/components/inventory/filter-bar";
import { Pager } from "@/components/inventory/pager";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { FixCell, KevBadge, ScoreLine, SeverityBadge } from "@/components/vuln/badges";
import { AdvisoryList, CveFacts } from "@/components/vuln/cve-facts";
import { AdvisoryLinks, SegmentedLinks, vulnHref } from "@/components/vuln/links";
import { UrlSheet } from "@/components/vuln/url-sheet";
import { hostTitle, requireHost } from "@/lib/host-page";
import {
  type FindingRow,
  type FixFilter,
  getHostFindingDetail,
  getHostFindings,
  getHostKernels,
  getHostVulnSummary,
  type KernelPackage,
} from "@/lib/queries-vulns";
import { oneOf, pageParam, param, type SearchParams, withParams } from "@/lib/search-params";
import { isVulnKey, SEVERITIES, SEVERITY_LABEL } from "@/lib/severity";
import { formatDate, formatDateTime } from "@/lib/time";

const PAGE_SIZE = 50;

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Vulnerabilities · ${hostTitle(host)}` };
}

export default async function HostVulnerabilitiesPage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}) {
  const { hostId } = await params;
  const sp = await searchParams;
  const { userId, host } = await requireHost(hostId);

  const status = oneOf(sp, "status", ["open", "resolved"] as const) ?? "open";
  const filters = {
    status,
    q: param(sp, "q"),
    severity: oneOf(sp, "severity", SEVERITIES),
    kev: param(sp, "kev") === "1",
    fix: oneOf<FixFilter>(sp, "fix", ["available", "pro", "none"]),
    sort: oneOf(sp, "sort", ["severity", "recent"] as const) ?? "severity",
    page: pageParam(sp),
    pageSize: PAGE_SIZE,
  };
  const rawV = param(sp, "v");
  const [{ rows, total }, summary, kernels, detail] = await Promise.all([
    getHostFindings(userId, host.id, filters),
    getHostVulnSummary(userId, host.id),
    getHostKernels(userId, host.id),
    rawV && isVulnKey(rawV) ? getHostFindingDetail(userId, host.id, rawV) : null,
  ]);
  // A ?v= this host has no finding for (or another user's) is a 404, like
  // the host itself.
  if (rawV && !detail) notFound();

  const basePath = `/dashboard/hosts/${host.id}/vulnerabilities`;
  const hasFilters = filters.q || filters.severity || filters.kev || filters.fix;

  return (
    <div className="flex flex-col gap-4">
      <KernelPanel
        kernels={kernels}
        runningKernel={host.runningKernel}
        unknownFindings={summary.runningKernelUnknown}
        packagesHref={`/dashboard/hosts/${host.id}/packages`}
      />

      <div className="flex flex-wrap items-center justify-between gap-3">
        <SegmentedLinks
          label="Finding status"
          items={[
            {
              href: `${basePath}${withParams(sp, { status: null, page: null, v: null, sort: null })}`,
              label: `Open (${summary.open})`,
              active: status === "open",
            },
            {
              href: `${basePath}${withParams(sp, { status: "resolved", page: null, v: null, sort: null })}`,
              label: `Resolved (${summary.resolved})`,
              active: status === "resolved",
            },
          ]}
        />
        {status === "open" && summary.open > 0 && (
          <div className="flex flex-wrap items-center gap-1.5">
            {SEVERITIES.filter((s) => summary.bySeverity[s] > 0).map((s) => (
              <Link
                key={s}
                href={`${basePath}${withParams(sp, { severity: filters.severity === s ? null : s, page: null, v: null })}`}
                title={`Show only ${SEVERITY_LABEL[s].toLowerCase()}`}
              >
                <SeverityBadge
                  severity={s}
                  count={summary.bySeverity[s]}
                  className={filters.severity === s ? "ring-ring ring-2" : undefined}
                />
              </Link>
            ))}
            {summary.kev > 0 && (
              <Link
                href={`${basePath}${withParams(sp, { kev: filters.kev ? null : "1", page: null, v: null })}`}
                title="Show only known-exploited"
              >
                <KevBadge
                  count={summary.kev}
                  className={filters.kev ? "ring-ring ring-2 ring-offset-1" : undefined}
                />
              </Link>
            )}
          </div>
        )}
      </div>

      <FilterBar
        action={basePath}
        q={filters.q}
        qPlaceholder="Filter by CVE or package…"
        qLabel="Search vulnerabilities"
        hidden={{ status: status === "resolved" ? "resolved" : null }}
        selects={[
          {
            name: "severity",
            label: "Severity",
            value: filters.severity,
            allLabel: "All severities",
            options: SEVERITIES.map((s) => ({
              value: s,
              label: SEVERITY_LABEL[s],
            })),
          },
          {
            name: "kev",
            label: "Known exploited",
            value: filters.kev ? "1" : null,
            allLabel: "KEV: any",
            options: [{ value: "1", label: "KEV only" }],
            className: "w-32",
          },
          {
            name: "fix",
            label: "Fix availability",
            value: filters.fix,
            allLabel: "Any fix status",
            options: [
              { value: "available", label: "Fix available" },
              { value: "pro", label: "Fix requires Pro" },
              { value: "none", label: "No fix yet" },
            ],
          },
          ...(status === "open"
            ? [
                {
                  name: "sort",
                  label: "Sort",
                  value: filters.sort,
                  options: [
                    { value: "severity", label: "Most urgent" },
                    { value: "recent", label: "Newest detected" },
                  ],
                },
              ]
            : []),
        ]}
      />

      <div className="bg-card rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Vulnerability</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>Package</TableHead>
              <TableHead>Installed</TableHead>
              <TableHead>Fixed in</TableHead>
              <TableHead>{status === "resolved" ? "Resolved" : "Detected"}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="text-muted-foreground h-24 text-center">
                  {hasFilters
                    ? "No vulnerabilities match these filters."
                    : status === "resolved"
                      ? "No vulnerabilities have been resolved on this host yet."
                      : host.inventory.length === 0
                        ? "No package inventory has been recorded for this host yet."
                        : "No open vulnerabilities on this host."}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((r) => (
                <FindingTableRow
                  key={`${r.sourcePackage}:${r.vulnKey}`}
                  r={r}
                  status={status}
                  sheetHref={`${basePath}${withParams(sp, { v: r.vulnKey })}`}
                />
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <Pager
        basePath={basePath}
        searchParams={sp}
        page={filters.page}
        pageSize={PAGE_SIZE}
        total={total}
      />

      {detail && rawV && (
        <UrlSheet
          key={rawV}
          closeHref={`${basePath}${withParams(sp, { v: null })}`}
          title={rawV}
          description={
            <Link href={vulnHref(rawV)} className="underline-offset-4 hover:underline">
              Fleet-wide view of {rawV}
            </Link>
          }
        >
          <div className="flex flex-col gap-4">
            <CveFacts cve={detail.cve} />
            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-semibold">On this host</h3>
              <ul className="flex flex-col gap-2">
                {detail.findings.map((f) => (
                  <li key={f.sourcePackage} className="rounded-lg border p-3 text-sm">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <SeverityBadge severity={f.severity} />
                      {f.isKev && <KevBadge />}
                      <span className="font-medium">{f.sourcePackage}</span>
                      {f.resolvedAt ? (
                        <Badge variant="outline" className="font-normal">
                          Resolved {formatDate(f.resolvedAt)}
                        </Badge>
                      ) : null}
                    </div>
                    <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
                      <dt className="text-muted-foreground">Binaries</dt>
                      <dd className="font-mono text-xs">{f.packages.join(", ") || "—"}</dd>
                      <dt className="text-muted-foreground">Installed</dt>
                      <dd className="font-mono text-xs">{f.installedVersion ?? "—"}</dd>
                      <dt className="text-muted-foreground">Fixed in</dt>
                      <dd>
                        <FixCell fixedVersion={f.fixedVersion} fixChannel={f.fixChannel} />
                        {f.fixAdvisoryId && (
                          <AdvisoryLinks ids={[f.fixAdvisoryId]} className="mt-1" />
                        )}
                      </dd>
                      <dt className="text-muted-foreground">Detected</dt>
                      <dd>
                        {formatDateTime(f.firstSeenAt)}
                        {f.reopenedAt && (
                          <span className="text-muted-foreground">
                            {" "}
                            · reopened {formatDate(f.reopenedAt)}
                            {f.reopenCount > 1 && ` (${f.reopenCount}×)`}
                          </span>
                        )}
                      </dd>
                      {f.kernelRelease && (
                        <>
                          <dt className="text-muted-foreground">Kernel</dt>
                          <dd className="font-mono text-xs">
                            {f.kernelRelease}
                            {f.runningKernelUnknown && (
                              <span className="text-muted-foreground font-sans">
                                {" "}
                                (running kernel unknown)
                              </span>
                            )}
                          </dd>
                        </>
                      )}
                    </dl>
                  </li>
                ))}
              </ul>
            </section>
            <section className="flex flex-col gap-2">
              <h3 className="text-sm font-semibold">Advisories</h3>
              <AdvisoryList advisories={detail.advisories} />
            </section>
          </div>
        </UrlSheet>
      )}
    </div>
  );
}

function FindingTableRow({
  r,
  status,
  sheetHref,
}: {
  r: FindingRow;
  status: "open" | "resolved";
  sheetHref: string;
}) {
  return (
    <TableRow>
      <TableCell className="max-w-md align-top">
        <Link href={sheetHref} scroll={false} className="font-medium hover:underline">
          {r.vulnKey}
        </Link>
        {r.description && (
          <p className="text-muted-foreground line-clamp-2 text-xs whitespace-normal">
            {r.description}
          </p>
        )}
      </TableCell>
      <TableCell className="align-top">
        <div className="flex flex-col items-start gap-1">
          <div className="flex flex-wrap gap-1">
            <SeverityBadge severity={r.severity} />
            {r.isKev && <KevBadge />}
          </div>
          <ScoreLine epss={r.epssScore} cvss={r.cvssV3Score} distroSeverity={r.distroSeverity} />
        </div>
      </TableCell>
      <TableCell className="align-top">
        <div className="flex flex-col">
          <span className="font-medium">{r.sourcePackage ?? "—"}</span>
          {r.packages.length > 0 &&
            !(r.packages.length === 1 && r.packages[0] === r.sourcePackage) && (
              <span
                className="text-muted-foreground line-clamp-2 max-w-56 text-xs whitespace-normal"
                title={r.packages.join(", ")}
              >
                {r.packages.join(", ")}
              </span>
            )}
          {r.runningKernelUnknown && (
            <span
              className="text-muted-foreground text-xs"
              title="The running kernel isn't known, so every installed kernel is counted"
            >
              kernel {r.kernelRelease ?? ""} · running kernel unknown
            </span>
          )}
        </div>
      </TableCell>
      <TableCell className="align-top font-mono text-xs">{r.installedVersion ?? "—"}</TableCell>
      <TableCell className="align-top">
        <FixCell fixedVersion={r.fixedVersion} fixChannel={r.fixChannel} />
      </TableCell>
      <TableCell className="text-muted-foreground align-top whitespace-nowrap">
        {status === "resolved" && r.resolvedAt ? (
          <span title={formatDateTime(r.resolvedAt)}>{formatDate(r.resolvedAt)}</span>
        ) : (
          <span title={formatDateTime(r.firstSeenAt)}>{formatDate(r.firstSeenAt)}</span>
        )}
        {r.reopenedAt && status === "open" && (
          <span className="block text-xs" title={formatDateTime(r.reopenedAt)}>
            reopened {formatDate(r.reopenedAt)}
          </span>
        )}
      </TableCell>
    </TableRow>
  );
}

// Installed kernels and whether findings cover them (running-kernel
// policy, DOMAIN_MODEL.md Q7): only the running kernel raises findings;
// when it's unknown, every installed kernel does.
function KernelPanel({
  kernels,
  runningKernel,
  unknownFindings,
  packagesHref,
}: {
  kernels: KernelPackage[];
  runningKernel: string | null;
  unknownFindings: number;
  packagesHref: string;
}) {
  if (kernels.length === 0 && unknownFindings === 0) return null;
  const unknown = runningKernel === null;
  // One row per kernel release; image + modules packages are listed together.
  const releases = new Map<string, KernelPackage[]>();
  for (const k of kernels) {
    const list = releases.get(k.kernelRelease) ?? [];
    list.push(k);
    releases.set(k.kernelRelease, list);
  }

  return (
    <Alert>
      {unknown ? <Info className="size-4" /> : <Cpu className="size-4" />}
      <AlertTitle>
        {unknown ? (
          "Running kernel unknown"
        ) : (
          <>
            Running kernel <span className="font-mono">{runningKernel}</span>
          </>
        )}
      </AlertTitle>
      <AlertDescription className="flex flex-col gap-2">
        <p>
          {unknown
            ? "This agent hasn't reported which kernel is running (it predates the kernel collector, or the collector failed), so vulnerabilities are raised for every installed kernel below. Update the agent to narrow them to the running one."
            : "Kernel vulnerabilities are raised only for the running kernel. Other installed kernels are listed for information: their matches apply if the host boots into them."}
        </p>
        {releases.size > 0 && (
          <ul className="flex flex-col gap-1">
            {[...releases].map(([rel, pkgs]) => {
              const running = pkgs[0].isRunning;
              const vulns = Math.max(...pkgs.map((p) => p.vulnCount));
              const fixable = Math.max(...pkgs.map((p) => p.fixableCount));
              return (
                <li key={rel} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-foreground font-mono text-xs">{rel}</span>
                  {running === true && <Badge variant="secondary">running</Badge>}
                  {running === false && (
                    <Badge variant="outline" className="font-normal">
                      not running · info only
                    </Badge>
                  )}
                  {running === null && (
                    <Badge variant="outline" className="border-dashed font-normal">
                      running state unknown
                    </Badge>
                  )}
                  <span className="text-xs">
                    {vulns} known {vulns === 1 ? "vulnerability" : "vulnerabilities"}
                    {vulns > 0 && `, ${fixable} fixable`}
                    {" · "}
                    <Link
                      href={`${packagesHref}?q=${encodeURIComponent(pkgs[0].name)}`}
                      className="underline-offset-4 hover:underline"
                    >
                      {pkgs.map((p) => p.name).join(", ")}
                    </Link>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </AlertDescription>
    </Alert>
  );
}
