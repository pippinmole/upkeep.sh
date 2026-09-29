import { FileChartColumn, FileText } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { EmptyState } from "@/components/empty-state";
import { PageHeader, SectionHeading } from "@/components/layout/page-header";
import { CHANNELS_URL } from "@/components/notifications/links";
import { Button } from "@/components/ui/button";
import { auth } from "@/lib/auth";
import { getChannels } from "@/lib/queries-notifications";
import { getRecentReports, getReportSchedules } from "@/lib/queries-reports";

import { RecentReports } from "./recent-reports";
import { AddScheduleButton, ReportsTable } from "./reports-table";

export const metadata: Metadata = { title: "Reports" };

const RECENT = 10;

// Report schedules and the newest reports across them. A schedule's full
// history is /dashboard/reports/schedules/[scheduleId]; one report is
// /dashboard/reports/[id] (the link in emails and ntfy).
export default async function ReportsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
  const [channels, schedules, recent] = await Promise.all([
    getChannels(userId),
    getReportSchedules(userId),
    getRecentReports(userId, RECENT),
  ]);
  const noChannels = channels.length === 0;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Reports"
        description="Scheduled patch lists for your whole estate, delivered to your channels."
        // The empty state carries the action when there are no schedules.
        actions={schedules.length > 0 && <AddScheduleButton channels={channels} />}
      />

      {schedules.length === 0 ? (
        <EmptyState
          icon={FileChartColumn}
          size="page"
          title="No report schedules yet"
          description="Alerts tell you when something changes; a report tells you where things stand: what to patch now, this week and when convenient, images to update, reboots, and agents that stopped reporting, compared with the previous report."
          steps={[
            {
              label: noChannels ? (
                <Link href={CHANNELS_URL} className="underline-offset-4 hover:underline">
                  Add a channel
                </Link>
              ) : (
                "Add a channel"
              ),
              done: !noChannels,
            },
            { label: "Create a schedule, for example every Monday morning", done: false },
          ]}
          action={
            noChannels ? (
              <Button asChild>
                <Link href={CHANNELS_URL}>Add a channel</Link>
              </Button>
            ) : (
              <AddScheduleButton channels={channels} />
            )
          }
        />
      ) : (
        <>
          <section aria-labelledby="schedules-heading" className="flex flex-col gap-3">
            <SectionHeading
              description={
                <>
                  &ldquo;Send now&rdquo; on a schedule sends a report straight away; its past
                  reports are one click away in the menu.
                </>
              }
            >
              <span id="schedules-heading">Schedules</span>
            </SectionHeading>
            <ReportsTable schedules={schedules} channels={channels} />
          </section>

          <section aria-labelledby="recent-heading" className="flex flex-col gap-3">
            <SectionHeading description={`The newest ${RECENT} across all schedules.`}>
              <span id="recent-heading">Recent reports</span>
            </SectionHeading>
            {recent.length === 0 ? (
              <EmptyState
                icon={FileText}
                size="inline"
                title="No reports yet"
                description="The first one is generated at the next scheduled time, or use “Send now” to get one straight away."
              />
            ) : (
              <RecentReports reports={recent} />
            )}
          </section>
        </>
      )}
    </main>
  );
}
