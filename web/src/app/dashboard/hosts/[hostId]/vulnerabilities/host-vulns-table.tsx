"use client";

import { useMemo } from "react";

import { DataTable, type DataTableServerState } from "@/components/data-table/data-table";
import { useServerTable } from "@/components/data-table/url-state";
import { KEV_FACET_OPTIONS, SEVERITY_FACET_OPTIONS } from "@/lib/image-tables";
import type { FindingRow } from "@/lib/queries-vulns";
import { FIX_FACET_OPTIONS, hostVulnsTable, KIND_FACET_OPTIONS } from "@/lib/vuln-tables";

import { hostVulnColumns } from "./host-vulns-columns";

// Server-driven host Vulnerabilities table: state in the URL
// (hostVulnsTable), one page of findings from getHostVulnList.
export function HostVulnsTable({
  hostId,
  rows,
  total,
  state,
  status,
  emptyMessage,
}: {
  hostId: string;
  rows: FindingRow[];
  total: number;
  state: DataTableServerState;
  status: "open" | "resolved";
  emptyMessage: string;
}) {
  const server = useServerTable(state, total, hostVulnsTable(status));
  const columns = useMemo(() => hostVulnColumns(status), [status]);
  const data = useMemo(() => rows.map((r) => ({ ...r, hostId })), [rows, hostId]);
  return (
    <DataTable
      columns={columns}
      data={data}
      getRowId={(r) =>
        [
          r.vulnKey,
          r.sourcePackage,
          r.image?.imageId,
          r.image?.os,
          r.image?.arch,
          r.image?.variant,
        ].join("|")
      }
      server={server}
      searchPlaceholder="Search CVE, package, image or container"
      facets={[
        { columnId: "kind", title: "Kind", options: KIND_FACET_OPTIONS },
        { columnId: "severity", title: "Severity", options: SEVERITY_FACET_OPTIONS },
        { columnId: "kev", title: "KEV", options: KEV_FACET_OPTIONS },
        { columnId: "fix", title: "Fix", options: FIX_FACET_OPTIONS },
      ]}
      emptyMessage={emptyMessage}
    />
  );
}
