import type { Metadata } from "next";
import Link from "next/link";

import { ALERTS_URL, NotificationSettingsLink } from "@/components/notifications/links";
import { getAlertRules } from "@/lib/queries-alerts";
import { getChannels, getScopeHosts } from "@/lib/queries-notifications";
import { requireViewer } from "@/lib/viewer";

import { AddRuleButton } from "./rule-actions";
import { RulesTable } from "./rules-table";

export const metadata: Metadata = { title: "Alert rules" };

export default async function AlertRulesPage() {
  const { workspaceId } = await requireViewer();
  const [rules, channels, hosts] = await Promise.all([
    getAlertRules(workspaceId),
    getChannels(workspaceId),
    getScopeHosts(workspaceId),
  ]);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex max-w-2xl flex-col gap-1">
          <h2 className="text-lg font-semibold">Alert rules</h2>
          <p className="text-muted-foreground text-sm">
            Each rule is a condition on your hosts (a listening port, a package, a vulnerability, a
            host that stopped reporting…). It fires once when a host starts matching and resolves
            when it stops. See what is firing under{" "}
            <Link
              href={ALERTS_URL}
              className="text-foreground font-medium underline underline-offset-4"
            >
              Alerts
            </Link>
            ; where notifications go is set up in <NotificationSettingsLink />.
          </p>
        </div>
        <AddRuleButton channels={channels} hosts={hosts} />
      </div>
      <RulesTable rules={rules} channels={channels} hosts={hosts} />
    </div>
  );
}
