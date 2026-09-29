import { formatDateTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

// Shared by the Hosts and Agents tables.

// DataTable numeric columns are right-aligned; the sort button's ghost
// padding moves to the right so the header lines up with the numbers.
export const NUMERIC_COLUMN = { className: "text-right tabular-nums" };
export const NUMERIC_HEADER = "-mr-3 ml-0";

// "2h ago", with the exact UTC time on hover.
export function TimeAgo({
  iso,
  fallback,
  className,
}: {
  iso: string | null;
  // Shown instead of "Never" when there is no time.
  fallback?: string;
  className?: string;
}) {
  if (!iso && fallback) return <span className={className}>{fallback}</span>;
  return (
    <time
      dateTime={iso ?? undefined}
      title={iso ? formatDateTime(iso) : undefined}
      className={cn("whitespace-nowrap", className)}
    >
      {relativeTime(iso)}
    </time>
  );
}
