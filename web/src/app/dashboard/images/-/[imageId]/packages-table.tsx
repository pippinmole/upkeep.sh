"use client";

import { DataTable, type DataTableServerState } from "@/components/data-table/data-table";
import { useServerTable } from "@/components/data-table/url-state";
import {
  IMAGE_PACKAGE_STATUSES,
  IMAGE_PACKAGE_STATUS_LABEL,
  PACKAGES_TABLE,
} from "@/lib/image-tables";
import type { ImagePackageRow } from "@/lib/queries-image-packages";

import { packageColumns } from "./packages-columns";

// Server-driven Packages table: one page of rows; search, facets, sort and
// paging are URL params the Server Component turns into SQL.
export function ImagePackagesTable({
  rows,
  total,
  state,
  ecosystems,
}: {
  rows: ImagePackageRow[];
  total: number;
  state: DataTableServerState;
  ecosystems: { ecosystem: string; packages: number }[];
}) {
  const server = useServerTable(state, total, PACKAGES_TABLE);
  return (
    <DataTable
      columns={packageColumns}
      data={rows}
      getRowId={(r) => r.softwareId}
      server={server}
      searchPlaceholder="Search package, source or path"
      facets={[
        {
          columnId: "ecosystem",
          title: "Ecosystem",
          options: ecosystems.map((e) => ({
            value: e.ecosystem,
            label: `${e.ecosystem} (${e.packages})`,
          })),
        },
        {
          columnId: "status",
          title: "Status",
          options: IMAGE_PACKAGE_STATUSES.map((s) => ({
            value: s,
            label: s === "vulnerable" ? "Vulnerable only" : IMAGE_PACKAGE_STATUS_LABEL[s],
          })),
        },
      ]}
      emptyMessage="No packages match these filters."
    />
  );
}
