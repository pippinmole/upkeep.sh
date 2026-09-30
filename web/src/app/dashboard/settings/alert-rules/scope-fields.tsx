"use client";

import Link from "next/link";

import { CheckList, FieldError as Err, toggle } from "@/components/notifications/shared";
import { Label } from "@/components/ui/label";
import type { ScopeHost } from "@/lib/queries-notifications";

// All hosts (including future ones) or picked hosts. Hosts have no tags
// yet (hosts.label is a display name), so there is no label scope.
export function ScopeFields({
  scope,
  hostIds,
  hosts,
  onScope,
  onHosts,
  error,
}: {
  scope: "all" | "selected";
  hostIds: string[];
  hosts: ScopeHost[];
  onScope: (s: "all" | "selected") => void;
  onHosts: (ids: string[]) => void;
  error?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label>Hosts</Label>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm">
        {(["all", "selected"] as const).map((s) => (
          <label key={s} className="flex items-center gap-2">
            <input
              type="radio"
              name="host-scope"
              className="accent-primary size-4"
              checked={scope === s}
              onChange={() => onScope(s)}
            />
            {s === "all" ? "All hosts (including future ones)" : "Selected hosts"}
          </label>
        ))}
      </div>
      {scope === "selected" &&
        (hosts.length === 0 ? (
          <p className="text-muted-foreground text-sm">
            Hosts appear here once an agent reports. See{" "}
            <Link
              href="/dashboard/hosts"
              className="text-foreground font-medium underline underline-offset-4"
            >
              Hosts
            </Link>
            .
          </p>
        ) : (
          <CheckList
            items={hosts}
            selected={hostIds}
            onToggle={(h) => onHosts(toggle(hostIds, h))}
            id={(h) => h.id}
            label={(h) => (
              <span>
                {h.label || h.hostname}
                {h.label && <span className="text-muted-foreground"> {h.hostname}</span>}
                {h.archived && <span className="text-muted-foreground"> (archived)</span>}
              </span>
            )}
          />
        ))}
      <Err msg={error} />
    </div>
  );
}
