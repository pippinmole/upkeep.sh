import { Send } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { EmptyState } from "@/components/empty-state";
import { SectionHeading } from "@/components/layout/page-header";
import { ALERTS_URL, REPORTS_URL } from "@/components/notifications/links";
import { auth } from "@/lib/auth";
import { getChannels } from "@/lib/queries-notifications";

import { AddChannelButton, ChannelsTable } from "./channels-table";

export const metadata: Metadata = { title: "Channels" };

const linkClass = "text-foreground font-medium underline underline-offset-4";

export default async function ChannelsPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const channels = await getChannels(session.user.id);

  return (
    <div className="flex flex-col gap-4">
      <SectionHeading
        description={
          <>
            Where notifications are delivered. What gets sent is decided by your{" "}
            <Link href={ALERTS_URL} className={linkClass}>
              alert rules
            </Link>{" "}
            and{" "}
            <Link href={REPORTS_URL} className={linkClass}>
              report schedules
            </Link>
            . Use &ldquo;Send test&rdquo; to check a channel end to end.
          </>
        }
        // The empty state carries the action when there are no channels.
        actions={channels.length > 0 && <AddChannelButton />}
      >
        Channels
      </SectionHeading>
      {channels.length === 0 ? (
        <EmptyState
          icon={Send}
          title="No channels yet"
          description="A channel is somewhere to send notifications: an email address, an ntfy topic or a webhook. Alert rules and scheduled reports both deliver to channels, so add one first."
          action={<AddChannelButton />}
        />
      ) : (
        <ChannelsTable channels={channels} />
      )}
    </div>
  );
}
