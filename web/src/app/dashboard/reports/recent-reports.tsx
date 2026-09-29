import Link from "next/link";

import { reportHref, scheduleReportsHref } from "@/components/notifications/links";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import type { RecentReportRow } from "@/lib/queries-reports";
import { formatRunAt } from "@/lib/report-schedules";
import { REPORT_SCHEMA_VERSION } from "@/lib/report-snapshot";
import { reportSummary } from "@/lib/report-summary";

import { DeliveryCountsCell } from "./schedules/[scheduleId]/past-reports-table";

// The newest reports across every schedule; a schedule's full history is
// on its past reports page.
export function RecentReports({ reports }: { reports: RecentReportRow[] }) {
  return (
    <div className="overflow-hidden rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Generated</TableHead>
            <TableHead>Schedule</TableHead>
            <TableHead>Summary</TableHead>
            <TableHead>Deliveries</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {reports.map((r) => {
            const supported = r.schemaVersion === REPORT_SCHEMA_VERSION;
            return (
              <TableRow key={r.id}>
                <TableCell className="whitespace-nowrap">
                  <Link
                    href={reportHref(r.id)}
                    className="font-medium underline-offset-4 hover:underline"
                  >
                    {formatRunAt(r.generatedAt, r.scheduleTimezone)}
                  </Link>
                  {r.trigger === "manual" && (
                    <Badge variant="outline" className="ml-2 font-normal">
                      Sent now
                    </Badge>
                  )}
                </TableCell>
                <TableCell>
                  <Link
                    href={scheduleReportsHref(r.scheduleId)}
                    className="block max-w-56 truncate underline-offset-4 hover:underline"
                    title={r.scheduleName}
                  >
                    {r.scheduleName}
                  </Link>
                </TableCell>
                <TableCell>
                  {/* Urgent actions lead the summary, so they get the danger tone. */}
                  <span
                    className={
                      supported && r.summary.headline.patch_now > 0
                        ? "text-danger-fg text-sm font-medium"
                        : "text-sm"
                    }
                  >
                    {supported ? reportSummary(r.summary) : "Unsupported format"}
                  </span>
                </TableCell>
                <TableCell>
                  <DeliveryCountsCell counts={r.deliveries} />
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}
