import { BellRing } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { NotificationSettingsLink } from "@/components/notifications/links";
import { auth } from "@/lib/auth";
import { getChannels, getRules, getScopeHosts } from "@/lib/queries-notifications";

import { AddRuleButton, RulesTable } from "./rules-table";

export const metadata: Metadata = { title: "Alert rules" };

export default async function RulesPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const userId = session.user.id;
  const [rules, channels, hosts] = await Promise.all([
    getRules(userId),
    getChannels(userId),
    getScopeHosts(userId),
  ]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted-foreground text-sm">
          Findings opened, reopened or resolved, and agents going stale or coming back. Channels are
          set up in <NotificationSettingsLink />.
        </p>
        <AddRuleButton channels={channels} hosts={hosts} />
      </div>
      {rules.length === 0 ? (
        <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
          <BellRing className="text-muted-foreground size-8" />
          <div>
            <h2 className="font-semibold">No alert rules yet</h2>
            <p className="text-muted-foreground mt-1 max-w-sm text-sm">
              {channels.length === 0 ? (
                <>
                  Add a channel first in <NotificationSettingsLink />, then create a rule that sends
                  to it.
                </>
              ) : (
                "Create a rule to get notified, for example about new critical or KEV findings."
              )}
            </p>
          </div>
        </div>
      ) : (
        <RulesTable rules={rules} channels={channels} hosts={hosts} />
      )}
    </div>
  );
}
