import { Bell } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { ALERTS_URL } from "@/components/notifications/links";
import { auth } from "@/lib/auth";
import { getChannels } from "@/lib/queries-notifications";

import { AddChannelButton, ChannelsTable } from "./channels-table";

export const metadata: Metadata = { title: "Notification settings" };

export default async function NotificationSettingsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const channels = await getChannels(session.user.id);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold">Notification settings</h2>
          <p className="text-muted-foreground text-sm">
            Channels are where notifications are delivered. Use &ldquo;Send test&rdquo; to check a
            channel end to end; what gets sent is decided by your{" "}
            <Link
              href={ALERTS_URL}
              className="text-foreground font-medium underline underline-offset-4"
            >
              alert rules
            </Link>
            .
          </p>
        </div>
        <AddChannelButton />
      </div>
      {channels.length === 0 ? (
        <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
          <Bell className="text-muted-foreground size-8" />
          <div>
            <h2 className="font-semibold">No channels yet</h2>
            <p className="text-muted-foreground mt-1 max-w-sm text-sm">
              Add a webhook or ntfy channel to receive notifications, then create an{" "}
              <Link
                href={ALERTS_URL}
                className="text-foreground font-medium underline underline-offset-4"
              >
                alert rule
              </Link>{" "}
              that sends to it.
            </p>
          </div>
        </div>
      ) : (
        <ChannelsTable channels={channels} />
      )}
    </div>
  );
}
