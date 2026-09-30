import { AlertTriangle } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { cache } from "react";

import { ChannelIcon } from "@/components/brand/channel-icon";
import { PageHeader } from "@/components/layout/page-header";
import {
  deliveryLogHref,
  REPORTS_URL,
  scheduleReportsHref,
} from "@/components/notifications/links";
import { DeliveryStatusBadge } from "@/components/notifications/shared";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { reportEmailModel } from "@/emails/report-content";
import { requireViewer } from "@/lib/viewer";
import { channelType } from "@/lib/notifiers";
import { getReport, type ReportDetail } from "@/lib/queries-reports";
import { formatRunAt } from "@/lib/report-schedules";
import { REPORT_SCHEMA_VERSION } from "@/lib/report-snapshot";
import { reportSummary } from "@/lib/report-summary";

import { HeadlineGrid, ReportSections } from "./report-view";

type Params = Promise<{ id: string }>;

// /dashboard/reports/<id> is the link target of report emails and ntfy
// (SW_DASHBOARD_URL + this path), so the path is fixed. Also reached from
// the Reports page and a schedule's past reports.

const loadReport = cache(async (id: string): Promise<ReportDetail | null> => {
  const { workspaceId } = await requireViewer();
  return getReport(workspaceId, id);
});

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const report = await loadReport((await params).id);
  return { title: report ? `${report.scheduleName} · Report` : "Report" };
}

function Deliveries({ report }: { report: ReportDetail }) {
  const notifications = [...new Set(report.deliveries.map((d) => d.notificationId))];
  return (
    <section
      aria-labelledby="deliveries-heading"
      className="border-border bg-card rounded-lg border p-4"
    >
      <h2 id="deliveries-heading" className="text-lg font-semibold">
        Deliveries
      </h2>
      {report.deliveries.length === 0 ? (
        <p className="text-muted-foreground text-sm">
          Not sent to any channel (the schedule had none, or the delivery log has been pruned).
        </p>
      ) : (
        <>
          <ul className="mt-2 flex flex-col gap-2">
            {report.deliveries.map((d) => (
              <li key={d.id} className="flex flex-wrap items-center gap-2 text-sm">
                <DeliveryStatusBadge status={d.status} />
                <ChannelIcon type={d.channelType} className="text-muted-foreground size-4" />
                <span>
                  {d.channelName}
                  <span className="text-muted-foreground">
                    {" "}
                    ({channelType(d.channelType)?.label ?? d.channelType}
                    {d.channelId === null && ", deleted"})
                  </span>
                </span>
                <span className="text-muted-foreground text-xs">
                  {d.attempts} {d.attempts === 1 ? "attempt" : "attempts"}
                </span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-sm">
            {notifications.map((n) => (
              <Link
                key={n}
                href={deliveryLogHref(n)}
                className="text-foreground font-medium underline underline-offset-4"
              >
                Open in the delivery log
              </Link>
            ))}
          </p>
        </>
      )}
    </section>
  );
}

export default async function ReportPage({ params }: { params: Params }) {
  const report = await loadReport((await params).id);
  if (!report) notFound();
  const s = report.snapshot;
  const supported = s?.schema_version === REPORT_SCHEMA_VERSION;
  const tz = supported ? s.schedule.timezone : report.scheduleTimezone;
  const model = supported ? reportEmailModel(s, null, Infinity) : null;
  const generated = formatRunAt(report.generatedAt, tz);

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <PageHeader
        breadcrumbs={[
          { label: "Reports", href: REPORTS_URL },
          { label: report.scheduleName, href: scheduleReportsHref(report.scheduleId) },
          { label: generated },
        ]}
        // The name at the time; the breadcrumb has the schedule's current name.
        title={supported ? s.schedule.name : report.scheduleName}
        badges={
          <Badge variant="outline" className="font-normal">
            {report.trigger === "manual" ? "Sent now" : "Scheduled"}
          </Badge>
        }
        meta={
          <span>
            Generated {generated}
            {model && <>. Covers {model.period}</>}.
          </span>
        }
        description={
          supported && <span className="text-foreground font-medium">{reportSummary(s)}</span>
        }
      />

      {!model ? (
        <Alert>
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>This report can&apos;t be shown</AlertTitle>
          <AlertDescription>
            It was stored in report format version {String(s?.schema_version ?? "unknown")}, and
            this version of upkeep.sh reads version {REPORT_SCHEMA_VERSION}. Its deliveries are
            below.
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <HeadlineGrid model={model} />
          {model.changeNotes.length > 0 ? (
            <div className="text-muted-foreground flex flex-col gap-1 text-sm">
              {model.changeNotes.map((n) => (
                <p key={n}>{n}</p>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">
              There is no previous report of this schedule to compare with.
            </p>
          )}
          <ReportSections model={model} s={s} />
          <p className="text-muted-foreground text-sm">Estate: {model.estate}</p>
        </>
      )}

      <Deliveries report={report} />
    </main>
  );
}
