import Link from "next/link";

// The page with every filter dropped. `hidden` params stay: they are view
// state (e.g. status=resolved), not filters. Server-safe, so pages and the
// client FilterBar build the same link.
export function clearFiltersHref(action: string, hidden?: Record<string, string | null>): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(hidden ?? {})) if (v) qs.set(k, v);
  const s = qs.toString();
  return s ? `${action}?${s}` : action;
}

// The no-results message for a filtered table (as opposed to an empty
// inventory, which gets an EmptyState).
export function NoMatches({ things, clearHref }: { things: string; clearHref: string }) {
  return (
    <p className="text-muted-foreground text-sm">
      No {things} match these filters.{" "}
      <Link href={clearHref} className="text-foreground underline underline-offset-4">
        Clear filters
      </Link>
    </p>
  );
}
