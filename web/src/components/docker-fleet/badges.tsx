import Link from "next/link";

import { containerStateTone, StatusBadge } from "@/components/status";

// Prefer <Badge variant="warning">; kept for callers that add it to an
// outline Badge's className.
export const WARN_BADGE = "border-warning/40 bg-warning/10 font-normal text-warning-fg";

// Container / task state, toned by containerStateTone.
export function ContainerStateBadge({ state }: { state: string | null }) {
  return (
    <StatusBadge
      tone={containerStateTone(state)}
      label={state ?? "unknown"}
      className="font-normal"
    />
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
