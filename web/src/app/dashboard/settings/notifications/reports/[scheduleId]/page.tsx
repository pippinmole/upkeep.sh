import { ArrowLeft, FileText } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { notFound, redirect } from "next/navigation";

import { NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";
import { EnabledBadge } from "@/components/notifications/shared";
import { auth } from "@/lib/auth";
import { getReportSchedule, getScheduleReports } from "@/lib/queries-reports";
import { cadenceSummary } from "@/lib/report-schedules";

import { SendNowButton } from "../../reports-table";
import { PastReportsTable, RefreshButton } from "./past-reports-table";

export const metadata: Metadata = { title: "Past reports" };

const LIMIT = 200;

// One schedule's past reports, newest first. The report page itself is
// /dashboard/reports/[id] (the link in emails and ntfy).
export default async function PastReportsPage({
  params,
}: {
  params: Promise<{ scheduleId: string }>;
}) {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
  const { scheduleId } = await params;
  const schedule = await getReportSchedule(userId, scheduleId);
  if (!schedule) notFound();
  const reports = await getScheduleReports(userId, schedule.id, LIMIT);

  return (
    <div className="flex flex-col gap-4">
      <div>
        <Link
          href={NOTIFICATION_SETTINGS_URL}
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm"
        >
          <ArrowLeft className="size-3.5" />
          Notification settings
        </Link>
        <div className="mt-2 flex flex-wrap items-end justify-between gap-2">
          <div>
            <h2 className="flex flex-wrap items-center gap-2 text-lg font-semibold">
              {schedule.name}
              <EnabledBadge enabled={schedule.enabled} />
            </h2>
            <p className="text-muted-foreground text-sm">
              {cadenceSummary(schedule)}. Past reports, newest first
              {reports.length === LIMIT && ` (the newest ${LIMIT} are shown)`}; each delivery is
              also in the delivery log.
            </p>
          </div>
          <div className="flex gap-2">
            <RefreshButton />
            <SendNowButton schedule={schedule} />
          </div>
        </div>
      </div>
      {reports.length === 0 ? (
        <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
          <FileText className="text-muted-foreground size-8" />
          <div>
            <h2 className="font-semibold">No reports yet</h2>
            <p className="text-muted-foreground mt-1 max-w-sm text-sm">
              The first one is generated at the next scheduled time, or use &ldquo;Send now&rdquo;
              to get one straight away.
            </p>
          </div>
        </div>
      ) : (
        <PastReportsTable reports={reports} timeZone={schedule.timezone} />
      )}
    </div>
  );
}
