import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

export const WARN_BADGE =
  "border-amber-600/40 bg-amber-400/15 font-normal text-amber-900 dark:text-amber-200";

// Container / task state. Running is the normal case; anything that isn't
// running but should be (restarting, dead) is flagged.
export function ContainerStateBadge({ state }: { state: string | null }) {
  const s = state ?? "unknown";
  const cls =
    s === "running"
      ? "border-emerald-600/40 bg-emerald-400/15 text-emerald-900 dark:text-emerald-200"
      : s === "restarting" || s === "dead"
        ? WARN_BADGE
        : "text-muted-foreground";
  return (
    <Badge variant="outline" className={cn("font-normal", cls)}>
      {s}
    </Badge>
  );
}

export function hostName(h: { hostname: string; label: string | null }): string {
  return h.label ? `${h.label} (${h.hostname})` : h.hostname;
}

export function HostLink({
  hostId,
  hostname,
  label,
  tab,
}: {
  hostId: string;
  hostname: string;
  label: string | null;
  tab?: "containers" | "images";
}) {
  return (
    <Link
      href={`/dashboard/hosts/${hostId}${tab ? `/${tab}` : ""}`}
      className="font-medium hover:underline"
    >
      {hostName({ hostname, label })}
    </Link>
  );
}

// "sha256:0123456789ab…" → "0123456789ab", the length `docker images` shows.
export function shortId(id: string): string {
  return id.replace(/^sha256:/, "").slice(0, 12);
}
