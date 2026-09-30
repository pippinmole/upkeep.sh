import { FileText } from "lucide-react";
import type { Metadata } from "next";
import { notFound } from "next/navigation";

import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/layout/page-header";
import { REPORTS_URL } from "@/components/notifications/links";
import { EnabledBadge } from "@/components/notifications/shared";
import { requireViewer } from "@/lib/viewer";
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
  const { workspaceId } = await requireViewer();
  const { scheduleId } = await params;
  const schedule = await getReportSchedule(workspaceId, scheduleId);
  if (!schedule) notFound();
  const reports = await getScheduleReports(workspaceId, schedule.id, LIMIT);

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        breadcrumbs={[{ label: "Reports", href: REPORTS_URL }, { label: schedule.name }]}
        title={schedule.name}
        badges={<EnabledBadge enabled={schedule.enabled} />}
        meta={<span>{cadenceSummary(schedule)}</span>}
        description={
          <>
            Past reports, newest first
            {reports.length === LIMIT && ` (the newest ${LIMIT} are shown)`}; each delivery is also
            in the delivery log.
          </>
        }
        actions={
          <>
            <RefreshButton />
            <SendNowButton schedule={schedule} />
          </>
        }
      />
      {reports.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No reports yet"
          description="The first one is generated at the next scheduled time, or use “Send now” to get one straight away."
          action={<SendNowButton schedule={schedule} />}
        />
      ) : (
        <PastReportsTable reports={reports} timeZone={schedule.timezone} />
      )}
    </main>
  );
}
