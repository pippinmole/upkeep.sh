import { Container, Package, ShieldCheck } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { EmptyState } from "@/components/empty-state";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { SegmentedLinks } from "@/components/vuln/links";
import { hostTitle, requireHost } from "@/lib/host-page";
import { hasHostVulnFilters, parseHostVulnFilters } from "@/lib/host-vulns-filters";
import { getHostVulnList } from "@/lib/queries-vuln-list";
import {
  getHostFindingDetail,
  getHostImageVulnSummary,
  getHostKernels,
  getHostVulnSummary,
  type VulnSummary,
} from "@/lib/queries-vulns";
import { param, type SearchParams, withParams } from "@/lib/search-params";
import { isVulnKey, SEVERITIES, SEVERITY_LABEL } from "@/lib/severity";
import { VULN_KIND_LABEL, type VulnKind } from "@/lib/vuln-tables";

import { ExportButton } from "./export-button";
import { FindingSheet } from "./finding-sheet";
import { HostVulnsTable } from "./host-vulns-table";
import { KernelPanel } from "./kernel-panel";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Vulnerabilities · ${hostTitle(host)}` };
}

// Host Vulnerabilities tab (DOMAIN_MODEL.md §3.5): the host's host package
// findings and the findings in images its containers run, in one
// server-driven table with a Kind facet; counts per kind, never summed.
export default async function HostVulnerabilitiesPage({
  params,
  searchParams,
}: {
  params: Params;
  searchParams: Promise<SearchParams>;
}) {
  const { hostId } = await params;
  const sp = await searchParams;
  const { workspaceId, host } = await requireHost(hostId);

  const { state, filters: parsed } = parseHostVulnFilters(sp);
  const { status } = parsed;
  const filters = {
    ...parsed,
    page: state.pagination.pageIndex + 1,
    pageSize: state.pagination.pageSize,
  };
  const rawV = param(sp, "v");
  const [{ rows, total }, pkgSummary, imageSummary, kernels, detail] = await Promise.all([
    getHostVulnList(workspaceId, host.id, filters),
    getHostVulnSummary(workspaceId, host.id),
    getHostImageVulnSummary(workspaceId, host.id),
    getHostKernels(workspaceId, host.id),
    rawV && isVulnKey(rawV) ? getHostFindingDetail(workspaceId, host.id, rawV) : null,
  ]);
  // A ?v= this host has no finding for (or another user's) is a 404, like
  // the host itself.
  if (rawV && !detail) notFound();

  const basePath = `/dashboard/hosts/${host.id}/vulnerabilities`;
  const filtered = hasHostVulnFilters(filters);
  const noneOpen = pkgSummary.open === 0 && imageSummary.open === 0;
  const statusHref = (s: "open" | "resolved") =>
    `${basePath}${withParams(sp, { status: s === "open" ? null : s, page: null, v: null, sort: null })}`;

  return (
    <div className="flex flex-col gap-4">
      <KernelPanel
        kernels={kernels}
        runningKernel={host.runningKernel}
        unknownFindings={pkgSummary.runningKernelUnknown}
        packagesHref={`/dashboard/hosts/${host.id}/packages`}
      />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <SegmentedLinks
          label="Finding status"
          items={[
            { href: statusHref("open"), label: "Open", active: status === "open" },
            { href: statusHref("resolved"), label: "Resolved", active: status === "resolved" },
          ]}
        />
        {total > 0 && (
          <ExportButton
            href={`${basePath}/export${withParams(sp, { page: null, v: null })}`}
            total={total}
            status={status}
            filtered={filtered}
          />
        )}
      </div>
      <div className="flex flex-col gap-1.5">
        {(["package", "image"] as const).map((k) => (
          <KindLine
            key={k}
            kind={k}
            summary={k === "package" ? pkgSummary : imageSummary}
            status={status}
            href={(set) => `${basePath}${withParams(sp, { ...set, page: null, v: null })}`}
          />
        ))}
      </div>

      {status === "open" && !filtered && noneOpen ? (
        host.inventory.length === 0 ? (
          <EmptyState
            icon={Package}
            title="No package inventory yet"
            description="Vulnerabilities are matched against the host's installed packages. They appear once the agent reports its first package inventory."
          />
        ) : (
          <EmptyState
            icon={ShieldCheck}
            title="No open vulnerabilities"
            description="No installed package on this host, or in the images its containers run, matches a known vulnerability."
          />
        )
      ) : (
        <HostVulnsTable
          key={status}
          hostId={host.id}
          rows={rows}
          total={total}
          state={state}
          status={status}
          emptyMessage={
            status === "resolved"
              ? "No vulnerabilities have been resolved on this host yet."
              : "Nothing on this page."
          }
        />
      )}

      {detail && rawV && (
        <FindingSheet
          hostId={host.id}
          vulnKey={rawV}
          detail={detail}
          closeHref={`${basePath}${withParams(sp, { v: null })}`}
        />
      )}
    </div>
  );
}

// One kind's counts: open (or resolved) findings, severity badges and KEV,
// each narrowing the table to that kind.
function KindLine({
  kind,
  summary,
  status,
  href,
}: {
  kind: VulnKind;
  summary: VulnSummary;
  status: "open" | "resolved";
  href: (set: Record<string, string | null>) => string;
}) {
  const Icon = kind === "image" ? Container : Package;
  const n = status === "open" ? summary.open : summary.resolved;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
      <Link
        href={href({ kind, severity: null, kev: null })}
        className="inline-flex items-center gap-1.5 hover:underline"
      >
        <Icon className="text-muted-foreground size-4" aria-hidden />
        <span className="font-medium">{VULN_KIND_LABEL[kind]}</span>
        <span className="tabular-nums">
          {n} {status}
        </span>
      </Link>
      {status === "open" && n > 0 && (
        <span className="flex flex-wrap items-center gap-1.5">
          {SEVERITIES.filter((s) => summary.bySeverity[s] > 0).map((s) => (
            <Link
              key={s}
              href={href({ kind, severity: s, kev: null })}
              title={`Show only ${SEVERITY_LABEL[s].toLowerCase()} in ${VULN_KIND_LABEL[kind].toLowerCase()}`}
            >
              <SeverityBadge severity={s} count={summary.bySeverity[s]} />
            </Link>
          ))}
          {summary.kev > 0 && (
            <Link href={href({ kind, severity: null, kev: "1" })} title="Show only known-exploited">
              <KevBadge count={summary.kev} />
            </Link>
          )}
        </span>
      )}
      <span className="text-muted-foreground text-xs">
        {kind === "image"
          ? "fixed by rebuilding or re-pulling the image"
          : "fixed by upgrading the host"}
      </span>
    </div>
  );
}
