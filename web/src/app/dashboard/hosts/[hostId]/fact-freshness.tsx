import type { LucideIcon } from "lucide-react";

import { collectorLabel } from "@/lib/host-page";
import type { FactFreshness } from "@/lib/queries-host-facts";
import type { CollectorStatus } from "@/lib/queries-inventory";
import { formatDateTime, relativeTime } from "@/lib/time";

// One line under a host fact tab's title: when the collector last
// confirmed the list and when it last changed, or why it's empty.
export function FactFreshnessNote({
  label,
  freshness,
}: {
  label: string;
  freshness: FactFreshness;
}) {
  if (!freshness) {
    return (
      <p className="text-muted-foreground text-sm">
        No {label} reported for this host yet. It needs an agent version with this collector, and
        the collector must succeed (see the collector notes above).
      </p>
    );
  }
  return (
    <p className="text-muted-foreground text-sm">
      {label[0].toUpperCase() + label.slice(1)} confirmed{" "}
      <span title={formatDateTime(freshness.confirmedAt)}>
        {relativeTime(freshness.confirmedAt)}
      </span>{" "}
      · last changed{" "}
      <span title={formatDateTime(freshness.changedAt)}>{relativeTime(freshness.changedAt)}</span>
    </p>
  );
}

// Shown in place of a host fact tab's table when it has no rows but the
// collector has reported (a never-reported list is explained by
// FactFreshnessNote). Distinguishes a genuinely empty list from one whose
// collector failed or was skipped in the latest snapshot, where the empty
// list is only the last successful result.
export function FactEmptyState({
  icon: Icon,
  title,
  description,
  collectors,
  collectorStatus,
}: {
  icon: LucideIcon;
  title: string;
  description: string;
  collectors: string[];
  collectorStatus: Record<string, CollectorStatus> | null | undefined;
}) {
  const statuses = collectors.map((name) => ({
    name,
    s: collectorStatus?.[name],
  }));
  const failed = statuses.filter(({ s }) => s?.status === "error");
  const skipped = statuses.filter(({ s }) => s?.status === "skipped");
  const labels = (xs: typeof statuses) => xs.map(({ name }) => collectorLabel(name)).join(", ");

  let heading = title;
  let body = description;
  if (failed.length > 0) {
    heading = "Couldn't collect this in the latest snapshot";
    body = `${labels(failed)} failed, so this may be out of date. The last successful collection found none.`;
  } else if (skipped.length === collectors.length) {
    const reasons = skipped.map(({ s }) => s?.reason).filter(Boolean);
    heading = "Not collected on this host";
    body = `${labels(skipped)} ${skipped.length === 1 ? "was" : "were"} skipped in the latest snapshot${reasons.length ? ` (${reasons.join("; ")})` : ""}.`;
  }

  return (
    <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
      <Icon className="text-muted-foreground size-8" />
      <div>
        <h3 className="font-semibold">{heading}</h3>
        <p className="text-muted-foreground mt-1 max-w-sm text-sm">{body}</p>
      </div>
    </div>
  );
}
