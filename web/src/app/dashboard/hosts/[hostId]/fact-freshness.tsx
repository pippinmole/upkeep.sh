import type { FactFreshness } from "@/lib/queries-host-facts";
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
