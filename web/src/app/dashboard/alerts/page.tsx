import { BellRing } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { tableStateFromParams } from "@/components/data-table/url-params";
import { EmptyState } from "@/components/empty-state";
import { ALERT_RULES_URL } from "@/components/notifications/links";
import { Button } from "@/components/ui/button";
import { ALERTS_TABLE } from "@/lib/alerts-table";
import { alertFilters, getAlertFacets, getAlerts } from "@/lib/queries-alerts";
import type { SearchParams } from "@/lib/search-params";
import { requireViewer } from "@/lib/viewer";

import { AlertsTable } from "./alerts-table";

export const metadata: Metadata = { title: "Alerts" };

// Alert instances, firing and resolved (docs/ALERTING.md). Firing first,
// then newest; ?host= / ?rule= / ?state= narrow it (host pages and rule
// rows link here).
export default async function AlertsPage({
  searchParams,
}: {
  searchParams: Promise<SearchParams>;
}) {
  const { workspaceId } = await requireViewer();
  const state = tableStateFromParams(await searchParams, ALERTS_TABLE);
  const [{ rows, total }, facets] = await Promise.all([
    getAlerts(workspaceId, alertFilters(state)),
    getAlertFacets(workspaceId),
  ]);
  const any = facets.states.some((s) => s.count > 0);

  if (!any) {
    return (
      <EmptyState
        icon={BellRing}
        title="No alerts yet"
        description="Alerts appear here when a host matches one of your alert rules, for example the default rule that watches for SSH (port 22) listening on a non-loopback address."
        action={
          <Button asChild>
            <Link href={ALERT_RULES_URL}>Alert rules</Link>
          </Button>
        }
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground text-sm">
        What your{" "}
        <Link
          href={ALERT_RULES_URL}
          className="text-foreground font-medium underline underline-offset-4"
        >
          alert rules
        </Link>{" "}
        found: each alert fires once when a host starts matching a rule and resolves when it stops.
        Resolved alerts are kept for 90 days.
      </p>
      <AlertsTable rows={rows} total={total} state={state} facets={facets} />
    </div>
  );
}
