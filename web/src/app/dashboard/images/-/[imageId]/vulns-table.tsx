"use client";

import { DataTable, type DataTableServerState } from "@/components/data-table/data-table";
import { useServerTable } from "@/components/data-table/url-state";
import {
  IMAGE_VULN_FIXES,
  IMAGE_VULN_FIX_LABEL,
  KEV_FACET_OPTIONS,
  SEVERITY_FACET_OPTIONS,
  VULNS_TABLE,
} from "@/lib/image-tables";
import type { ImageVulnRow } from "@/lib/queries-image-vulns";

import { vulnColumns } from "./vulns-columns";

// Server-driven Vulnerabilities table (see ImagePackagesTable).
export function ImageVulnsTable({
  rows,
  total,
  state,
  emptyMessage,
}: {
  rows: ImageVulnRow[];
  total: number;
  state: DataTableServerState;
  emptyMessage: string;
}) {
  const server = useServerTable(state, total, VULNS_TABLE);
  return (
    <DataTable
      columns={vulnColumns}
      data={rows}
      getRowId={(r) => `${r.sourcePackage}:${r.vulnKey}`}
      server={server}
      searchPlaceholder="Search CVE or package"
      facets={[
        { columnId: "severity", title: "Severity", options: SEVERITY_FACET_OPTIONS },
        { columnId: "kev", title: "KEV", options: KEV_FACET_OPTIONS },
        {
          columnId: "fix",
          title: "Fix",
          options: IMAGE_VULN_FIXES.map((f) => ({ value: f, label: IMAGE_VULN_FIX_LABEL[f] })),
        },
      ]}
      emptyMessage={emptyMessage}
    />
  );
}
