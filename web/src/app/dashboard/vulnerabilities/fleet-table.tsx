"use client";

import { useMemo } from "react";

import { DataTable, type DataTableServerState } from "@/components/data-table/data-table";
import { useServerTable } from "@/components/data-table/url-state";
import { KEV_FACET_OPTIONS, SEVERITY_FACET_OPTIONS } from "@/lib/image-tables";
import type { FleetVulnRow } from "@/lib/queries-vuln-list";
import { FIX_FACET_OPTIONS, FLEET_VULNS_TABLE, KIND_FACET_OPTIONS } from "@/lib/vuln-tables";

import { fleetColumns } from "./fleet-columns";

// Server-driven fleet Vulnerabilities table: state in the URL
// (FLEET_VULNS_TABLE), one page of rows from getFleetVulnList.
export function FleetVulnsTable({
  rows,
  total,
  state,
  status,
  emptyMessage,
}: {
  rows: FleetVulnRow[];
  total: number;
  state: DataTableServerState;
  status: "open" | "resolved";
  emptyMessage: string;
}) {
  const server = useServerTable(state, total, FLEET_VULNS_TABLE);
  const columns = useMemo(() => fleetColumns(status), [status]);
  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(r) =>
        r.image
          ? `${r.vulnKey}|${r.image.imageId}|${r.image.os}|${r.image.arch}|${r.image.variant}`
          : r.vulnKey
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
