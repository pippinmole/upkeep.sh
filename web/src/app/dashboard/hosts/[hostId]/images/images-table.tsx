"use client";

import type { FilterFn } from "@tanstack/react-table";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper, type DataTableFeatures } from "@/components/data-table/features";
import { Badge } from "@/components/ui/badge";
import type { HostImageRow } from "@/lib/queries-docker";
import { formatDateTime, relativeTime } from "@/lib/time";

const USE_OPTIONS = [
  { value: "running", label: "Used by a running container" },
  { value: "stopped", label: "Used by stopped containers only" },
  { value: "unused", label: "Not used by any container" },
];
const use = (i: HostImageRow) =>
  i.running > 0 ? "running" : i.containers > 0 ? "stopped" : "unused";

const shortId = (id: string) => (id.startsWith("sha256:") ? id.slice(7, 19) : id.slice(0, 12));

const col = dataTableColumnHelper<HostImageRow>();

const columns = col.columns([
  col.accessor((i) => i.repoTags[0] ?? "", {
    id: "tags",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Repository tags" />,
    enableHiding: false,
    cell: ({ row }) => {
      const i = row.original;
      return (
        <div className="flex min-w-0 flex-col gap-0.5">
          {i.repoTags.length > 0 ? (
            i.repoTags.map((t) => (
              <span key={t} className="block max-w-80 truncate font-mono text-sm" title={t}>
                {t}
              </span>
            ))
          ) : (
            <span className="text-muted-foreground text-sm">Untagged</span>
          )}
          {i.repoDigests.length > 0 && (
            <span
              className="text-muted-foreground w-fit cursor-help text-xs underline decoration-dotted"
              title={i.repoDigests.join("\n")}
            >
              {i.repoDigests.length} {i.repoDigests.length === 1 ? "digest" : "digests"}
            </span>
          )}
          {i.inspectError && (
            <span
              className="text-muted-foreground w-fit cursor-help text-xs underline decoration-dotted"
              title={`The latest push couldn't inspect this image: ${i.inspectError}`}
            >
              Partial: details unavailable
            </span>
          )}
        </div>
      );
    },
  }),
  col.accessor("imageId", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Image ID" />,
    cell: ({ row }) => (
      <span className="font-mono text-xs" title={row.original.imageId}>
        {shortId(row.original.imageId)}
      </span>
    ),
  }),
  col.accessor((i) => i.created ?? "", {
    id: "created",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
    sortFn: (a, b) => Date.parse(a.original.created ?? "0") - Date.parse(b.original.created ?? "0"),
    cell: ({ row }) =>
      row.original.created ? (
        <span
          className="text-muted-foreground whitespace-nowrap"
          title={formatDateTime(row.original.created)}
        >
          {relativeTime(row.original.created)}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
  }),
  col.accessor((i) => [i.os, i.arch, i.variant].filter(Boolean).join("/"), {
    id: "platform",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Platform" />,
    cell: ({ getValue }) => {
      const v = getValue();
      return v ? (
        <span className="font-mono text-xs">{v}</span>
      ) : (
        <span className="text-muted-foreground" title="Not inspected on this host yet">
          Unknown
        </span>
      );
    },
  }),
  col.accessor(use, {
    id: "use",
    header: ({ column }) => <DataTableColumnHeader column={column} title="In use" />,
    filterFn: "arrHas",
    sortFn: (a, b) =>
      a.original.running - b.original.running || a.original.containers - b.original.containers,
    cell: ({ row }) => {
      const i = row.original;
      if (i.containers === 0) return <span className="text-muted-foreground">Not used</span>;
      return (
        <Badge
          variant="outline"
          className={
            i.running > 0
              ? "border-emerald-600/40 bg-emerald-500/10 whitespace-nowrap text-emerald-800 dark:text-emerald-200"
              : "text-muted-foreground whitespace-nowrap"
          }
          title={`${i.running} running of ${i.containers} ${i.containers === 1 ? "container" : "containers"}`}
        >
          {i.containers} {i.containers === 1 ? "container" : "containers"}
          {i.running > 0 && i.running < i.containers ? ` (${i.running} running)` : ""}
        </Badge>
      );
    },
  }),
  col.accessor("since", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="On host since" />,
    sortFn: (a, b) => Date.parse(a.original.since) - Date.parse(b.original.since),
    cell: ({ row }) => (
      <span
        className="text-muted-foreground whitespace-nowrap"
        title={`${formatDateTime(row.original.since)} (with these tags; first seen by the agent)`}
      >
        {relativeTime(row.original.since)}
      </span>
    ),
  }),
]);

const search: FilterFn<DataTableFeatures, HostImageRow> = (row, _id, value) => {
  const q = String(value ?? "")
    .trim()
    .toLowerCase();
  if (!q) return true;
  const i = row.original;
  return [i.imageId, ...i.repoTags, ...i.repoDigests].some((v) => v.toLowerCase().includes(q));
};

export function ImagesTable({ rows }: { rows: HostImageRow[] }) {
  return (
    <DataTable
      columns={columns}
      data={rows}
      getRowId={(i) => i.imageId}
      globalFilterFn={search}
      searchPlaceholder="Search tags, digests or IDs"
      facets={[{ columnId: "use", title: "In use", options: USE_OPTIONS }]}
      initialSorting={[{ id: "tags", desc: false }]}
      pageSize={50}
      emptyMessage="No images match."
    />
  );
}
