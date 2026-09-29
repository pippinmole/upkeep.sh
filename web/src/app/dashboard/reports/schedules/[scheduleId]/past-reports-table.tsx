"use client";

import { RefreshCw } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useTransition } from "react";

import { DataTable } from "@/components/data-table/data-table";
import { DataTableColumnHeader } from "@/components/data-table/data-table-column-header";
import { dataTableColumnHelper } from "@/components/data-table/features";
import { reportHref } from "@/components/notifications/links";
import { DeliveryStatusBadge } from "@/components/notifications/shared";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import type { DeliveryCounts, PastReportRow } from "@/lib/queries-reports";
import { formatRunAt } from "@/lib/report-schedules";
import { REPORT_SCHEMA_VERSION } from "@/lib/report-snapshot";
import { reportSummary } from "@/lib/report-summary";

const STATUSES: (keyof DeliveryCounts)[] = ["failed", "retrying", "pending", "delivered"];

// "Failed 1  Delivered 2"; "Not sent" when the report went to no channel
// (every channel deleted) or its notification was pruned.
export function DeliveryCountsCell({ counts }: { counts: DeliveryCounts }) {
  const present = STATUSES.filter((s) => counts[s] > 0);
  if (present.length === 0) return <span className="text-muted-foreground">Not sent</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {present.map((s) => (
        <span key={s} className="inline-flex items-center gap-1">
          <DeliveryStatusBadge status={s} />
          <span className="text-muted-foreground text-xs tabular-nums">{counts[s]}</span>
        </span>
      ))}
    </span>
  );
}

const col = dataTableColumnHelper<PastReportRow>();

function makeColumns(timeZone: string) {
  return col.columns([
    col.accessor((r) => Date.parse(r.generatedAt), {
      id: "generatedAt",
      header: ({ column }) => <DataTableColumnHeader column={column} title="Generated" />,
      enableHiding: false,
      cell: ({ row }) => (
        <Link
          href={reportHref(row.original.id)}
          className="font-medium whitespace-nowrap underline-offset-4 hover:underline"
        >
          {formatRunAt(row.original.generatedAt, timeZone)}
        </Link>
      ),
    }),
    col.accessor("trigger", {
      header: ({ column }) => <DataTableColumnHeader column={column} title="Trigger" />,
      cell: ({ row }) => (
        <Badge variant="outline" className="font-normal whitespace-nowrap">
          {row.original.trigger === "manual" ? "Sent now" : "Scheduled"}
        </Badge>
      ),
    }),
    col.accessor(
      (r) =>
        r.schemaVersion === REPORT_SCHEMA_VERSION ? reportSummary(r.summary) : "Unsupported format",
      {
        id: "summary",
        header: "Summary",
        enableSorting: false,
        cell: ({ getValue }) => <span className="text-sm">{getValue()}</span>,
      },
    ),
    col.display({
      id: "deliveries",
      header: "Deliveries",
      cell: ({ row }) => <DeliveryCountsCell counts={row.original.deliveries} />,
    }),
  ]);
}

// A report sent now shows up a few seconds after the button is pressed.
export function RefreshButton() {
  const router = useRouter();
  const [refreshing, startRefresh] = useTransition();
  return (
    <Button variant="outline" onClick={() => startRefresh(() => router.refresh())}>
      <RefreshCw className={refreshing ? "animate-spin" : undefined} />
      Refresh
    </Button>
  );
}

export function PastReportsTable({
  reports,
  timeZone,
}: {
  reports: PastReportRow[];
  timeZone: string;
}) {
  return (
    <DataTable
      columns={makeColumns(timeZone)}
      data={reports}
      getRowId={(r) => r.id}
      searchPlaceholder="Search reports"
      initialSorting={[{ id: "generatedAt", desc: true }]}
      emptyMessage="No reports match."
    />
  );
}
