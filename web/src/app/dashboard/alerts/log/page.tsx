import { ScrollText } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { EmptyState } from "@/components/empty-state";
import { NotificationSettingsLink } from "@/components/notifications/links";
import { requireViewer } from "@/lib/viewer";
import { getDeliveries } from "@/lib/queries-notifications";

import { DeliveriesTable } from "./deliveries-table";

export const metadata: Metadata = { title: "Delivery log" };

const LIMIT = 500;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ?notification=<id> narrows the log to one notification's deliveries (the
// report page links here); anything else in it is ignored.
export default async function DeliveryLogPage({
  searchParams,
}: {
  searchParams: Promise<{ notification?: string | string[] }>;
}) {
  const { workspaceId } = await requireViewer();
  const raw = (await searchParams).notification;
  const notificationId = typeof raw === "string" && UUID_RE.test(raw) ? raw : null;
  const deliveries = await getDeliveries(workspaceId, LIMIT, notificationId);

  return (
    <div className="flex flex-col gap-4">
      {notificationId ? (
        <p className="text-muted-foreground text-sm">
          Showing the deliveries of one notification.{" "}
          <Link
            href="/dashboard/alerts/log"
            className="text-foreground font-medium underline underline-offset-4"
          >
            Show all
          </Link>
        </p>
      ) : (
        <p className="text-muted-foreground text-sm">
          Every notification sent to each channel, with each attempt&apos;s response. Failed
          attempts are retried with backoff for about 11 hours. The newest {LIMIT} are shown; the
          log keeps 90 days.
        </p>
      )}
      {deliveries.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="Nothing sent yet"
          description={
            notificationId ? (
              "No deliveries for this notification (the log keeps 90 days)."
            ) : (
              <>
                Deliveries show up here once a rule matches or a report is sent, or when you send a
                test from <NotificationSettingsLink />.
              </>
            )
          }
        />
      ) : (
        <DeliveriesTable deliveries={deliveries} />
      )}
    </div>
  );
}
