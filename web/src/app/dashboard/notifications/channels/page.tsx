import { Bell } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
import { getChannels } from "@/lib/queries-notifications";

import { AddChannelButton, ChannelsTable } from "./channels-table";

export const metadata: Metadata = { title: "Notification channels" };

export default async function ChannelsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const channels = await getChannels(session.user.id);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted-foreground text-sm">
          Where notifications are delivered. Use &ldquo;Send test&rdquo; to check a channel end to
          end.
        </p>
        <AddChannelButton />
      </div>
      {channels.length === 0 ? (
        <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
          <Bell className="text-muted-foreground size-8" />
          <div>
            <h2 className="font-semibold">No channels yet</h2>
            <p className="text-muted-foreground mt-1 max-w-sm text-sm">
              Add a webhook to receive signed JSON notifications, then create a rule that sends to
              it.
            </p>
          </div>
        </div>
      ) : (
        <ChannelsTable channels={channels} />
      )}
    </div>
  );
}
