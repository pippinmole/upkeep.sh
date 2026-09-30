import type { TableUrlOptions } from "@/components/data-table/url-params";

// URL state of the Alerts list (/dashboard/alerts), shared by the Server
// Component (parsing, SQL allowlists) and the client table. Client-safe.
// ?host=<id> is also the link the worker puts in alert notifications
// (server/internal/store/alerting.go eventURL), so keep that key.

export const ALERT_STATES = ["firing", "resolved"] as const;
export type AlertState = (typeof ALERT_STATES)[number];

export const ALERT_STATE_LABEL: Record<AlertState, string> = {
  firing: "Firing",
  resolved: "Resolved",
};

export const RESOLVED_REASON_LABEL: Record<string, string> = {
  cleared: "Condition cleared",
  rule_changed: "Rule edited",
  rule_disabled: "Rule disabled",
  rule_deleted: "Rule deleted",
  out_of_scope: "Host left the rule's scope",
  host_archived: "Host archived",
};

export const ALERT_SORTS = ["state", "fired", "resolved", "host", "rule"] as const;
export type AlertSort = (typeof ALERT_SORTS)[number];

// Default: firing first, then newest.
export const ALERTS_TABLE: TableUrlOptions = {
  sortKeys: ALERT_SORTS,
  filterKeys: ["state", "rule", "host"],
  defaultSort: { id: "state", desc: false },
  defaultPageSize: 50,
};

export function hostAlertsHref(hostId: string): string {
  return `/dashboard/alerts?host=${encodeURIComponent(hostId)}`;
}
