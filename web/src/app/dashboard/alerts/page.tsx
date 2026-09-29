import { BellRing } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { EmptyState } from "@/components/empty-state";
import { CHANNELS_URL } from "@/components/notifications/links";
import { Button } from "@/components/ui/button";
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
  const noChannels = channels.length === 0;

  if (rules.length === 0) {
    return (
      <EmptyState
        icon={BellRing}
        title="No alert rules yet"
        description="A rule picks the events worth telling you about (findings opened, reopened or resolved, agents going stale or coming back) and the channels to send them to. For example: new critical or KEV findings, straight to email."
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
          { label: "Create a rule", done: false },
        ]}
        action={
          noChannels ? (
            <Button asChild>
              <Link href={CHANNELS_URL}>Add a channel</Link>
            </Button>
          ) : (
            <AddRuleButton channels={channels} hosts={hosts} />
          )
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-muted-foreground text-sm">
          Findings opened, reopened or resolved, and agents going stale or coming back.
        </p>
        <AddRuleButton channels={channels} hosts={hosts} />
      </div>
      <RulesTable rules={rules} channels={channels} hosts={hosts} />
    </div>
  );
}
