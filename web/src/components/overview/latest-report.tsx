import { FileText } from "lucide-react";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { LatestReport } from "@/lib/queries-overview";
import { reportSummary } from "@/lib/report-summary";
import { formatDateTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

// The Overview's "Latest report" card: the newest generated report of any
// schedule, its one-line summary and headline numbers.

export function LatestReportCard({
  report,
  className,
}: {
  report: LatestReport | null;
  className?: string;
}) {
  return (
    <Card className={cn("gap-4", className)}>
      <CardHeader>
        <CardTitle>Latest report</CardTitle>
        {report && (
          <CardDescription>
            {report.scheduleName} ·{" "}
            <time dateTime={report.generatedAt} title={formatDateTime(report.generatedAt)}>
              {relativeTime(report.generatedAt)}
            </time>
            {report.trigger === "manual" && " · sent manually"}
          </CardDescription>
        )}
        <CardAction>
          <Link
            href="/dashboard/reports"
            className="text-muted-foreground hover:text-foreground text-sm hover:underline"
          >
            All reports
          </Link>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-4">
        {report ? (
          <>
            <p className="text-sm first-letter:uppercase">{reportSummary(report.summary)}</p>
            <dl className="grid grid-cols-2 gap-3">
              <Metric label="Patch now" value={report.summary.headline.patch_now} />
              <Metric label="Patch this week" value={report.summary.headline.patch_this_week} />
              <Metric label="Images to update" value={report.summary.headline.images_to_update} />
              <Metric label="Open findings" value={report.summary.headline.total_open_findings} />
            </dl>
            <Button asChild variant="outline" size="sm" className="mt-auto self-start">
              <Link href={`/dashboard/reports/${report.id}`}>Open report</Link>
            </Button>
          </>
        ) : (
          <EmptyState
            size="inline"
            icon={FileText}
            title="No reports yet"
            description="Schedule a weekly or monthly summary of what to patch first."
            action={
              <Button asChild size="sm" variant="outline">
                <Link href="/dashboard/reports">Schedule a report</Link>
              </Button>
            }
          />
        )}
      </CardContent>
    </Card>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="flex flex-col">
      <dt className="text-muted-foreground text-xs">{label}</dt>
      <dd className="text-lg font-semibold tabular-nums">{value.toLocaleString("en-US")}</dd>
    </div>
  );
}
