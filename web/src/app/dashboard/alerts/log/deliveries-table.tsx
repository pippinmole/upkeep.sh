"use client";

import { ChevronRight, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { ChannelIcon } from "@/components/brand/channel-icon";
import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { reportHref } from "@/components/notifications/links";
import { DeliveryError } from "@/components/response-body";
import { Button } from "@/components/ui/button";
import { channelType } from "@/lib/notifiers";
import type { DeliveryRow } from "@/lib/queries-notifications";
import { formatDateTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

import { DELIVERY_STATUS_OPTIONS, DeliveryStatusBadge } from "@/components/notifications/shared";

const KIND_OPTIONS = [
  { value: "alert", label: "Alert" },
  { value: "digest", label: "Digest" },
  { value: "test", label: "Test" },
  { value: "report", label: "Report" },
];

function Attempts({ d }: { d: DeliveryRow }) {
  if (d.attemptLog.length === 0) {
    return <p className="text-muted-foreground px-12 py-3 text-sm">Not attempted yet.</p>;
  }
  return (
    <div className="overflow-x-auto px-4 py-2 sm:pl-12">
      <table className="w-full text-sm">
        <thead className="text-muted-foreground text-left text-xs">
          <tr>
            <th className="py-1.5 pr-4 font-medium">Attempt</th>
            <th className="py-1.5 pr-4 font-medium">At</th>
            <th className="py-1.5 pr-4 font-medium">Response</th>
            <th className="py-1.5 pr-4 font-medium">Duration</th>
            <th className="py-1.5 font-medium">Error</th>
          </tr>
        </thead>
        <tbody>
          {d.attemptLog.map((a) => (
            <tr key={a.attempt} className="border-border/60 border-t align-top">
              <td className="py-2 pr-4 tabular-nums">{a.attempt}</td>
              <td className="py-2 pr-4 whitespace-nowrap">{formatDateTime(a.attemptedAt)}</td>
              <td className="py-2 pr-4 tabular-nums">{a.statusCode ?? "—"}</td>
              <td className="py-2 pr-4 tabular-nums">{a.durationMs} ms</td>
              <td className="py-2">{a.error && <DeliveryError error={a.error} />}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

const col = dataTableColumnHelper<DeliveryRow>();

const columns = col.columns([
  col.display({
    id: "expand",
    enableHiding: false,
    cell: ({ row }) => (
      <Button
        variant="ghost"
        size="icon"
        className="size-7"
        onClick={row.getToggleExpandedHandler()}
        aria-expanded={row.getIsExpanded()}
        aria-label={row.getIsExpanded() ? "Hide attempts" : "Show attempts"}
      >
        <ChevronRight
          className={cn("size-4 transition-transform", row.getIsExpanded() && "rotate-90")}
        />
      </Button>
    ),
  }),
  col.accessor((d) => Date.parse(d.createdAt), {
    id: "createdAt",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Created" />,
    cell: ({ row }) => (
      <span className="whitespace-nowrap" title={formatDateTime(row.original.createdAt)}>
        {relativeTime(row.original.createdAt)}
      </span>
    ),
  }),
  col.accessor("status", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Status" />,
    filterFn: "arrHas",
    cell: ({ row }) => <DeliveryStatusBadge status={row.original.status} />,
  }),
  col.accessor("kind", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Kind" />,
    filterFn: "arrHas",
    cell: ({ row }) => KIND_OPTIONS.find((k) => k.value === row.original.kind)?.label,
  }),
  col.accessor("channelName", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Channel" />,
    cell: ({ row }) => {
      const d = row.original;
      const type = `${channelType(d.channelType)?.label ?? d.channelType}${d.channelId === null ? ", deleted" : ""}`;
      return (
        <span
          className="inline-flex max-w-64 items-center gap-1.5 whitespace-nowrap"
          title={`${d.channelName} (${type})`}
        >
          <ChannelIcon type={d.channelType} className="text-muted-foreground size-4 shrink-0" />
          <span className="truncate">
            {d.channelName}
            <span className="text-muted-foreground"> ({type})</span>
          </span>
        </span>
      );
    },
  }),
  col.accessor((d) => d.ruleName ?? "", {
    id: "rule",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Rule" />,
    cell: ({ getValue }) =>
      getValue() ? (
        <span className="block max-w-48 truncate" title={getValue()}>
          {getValue()}
        </span>
      ) : (
        <span className="text-muted-foreground">—</span>
      ),
  }),
  col.accessor("summary", {
    header: "Summary",
    enableSorting: false,
    cell: ({ row }) =>
      row.original.reportId ? (
        <Link
          href={reportHref(row.original.reportId)}
          className="block max-w-96 truncate underline-offset-4 hover:underline"
          title={row.original.summary}
        >
          {row.original.summary}
        </Link>
      ) : (
        <span className="block max-w-96 truncate" title={row.original.summary}>
          {row.original.summary}
        </span>
      ),
  }),
  col.accessor("attempts", {
    header: ({ column }) => <DataTableColumnHeader column={column} title="Attempts" />,
    cell: ({ row }) => <span className="tabular-nums">{row.original.attempts}</span>,
  }),
  col.accessor((d) => d.lastStatusCode ?? 0, {
    id: "code",
    header: ({ column }) => <DataTableColumnHeader column={column} title="Response" />,
    cell: ({ row }) => (
      <span className="tabular-nums" title={row.original.lastError ?? undefined}>
        {row.original.lastStatusCode ?? "—"}
      </span>
    ),
  }),
]);

export function DeliveriesTable({ deliveries }: { deliveries: DeliveryRow[] }) {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  return (
    <div className="flex flex-col gap-3">
      <div className="flex justify-end">
        <Button variant="outline" size="sm" onClick={() => startRefresh(() => router.refresh())}>
          <RefreshCw className={refreshing ? "animate-spin" : undefined} />
          Refresh
        </Button>
      </div>
      <DataTable
        columns={columns}
        data={deliveries}
        getRowId={(d) => d.id}
        getRowCanExpand={() => true}
        renderSubRows={(row) => <Attempts d={row.original} />}
        searchPlaceholder="Search channel, rule or summary"
        facets={[
          { columnId: "status", title: "Status", options: DELIVERY_STATUS_OPTIONS },
          { columnId: "kind", title: "Kind", options: KIND_OPTIONS },
        ]}
        initialSorting={[{ id: "createdAt", desc: true }]}
        emptyMessage="No deliveries match."
      />
    </div>
  );
}
