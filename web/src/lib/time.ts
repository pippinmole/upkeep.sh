// Small hand-rolled relative-time formatter so we don't pull in date-fns
// for a single string ("2h ago"). Good enough for the agents list; revisit
// if more date formatting shows up elsewhere.
export function relativeTime(iso: string | null): string {
  if (!iso) return "Never";

  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "Never";

  const diffMs = Date.now() - then;
  if (diffMs < 0) return "Just now";

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return "Just now";

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;

  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;

  const years = Math.floor(months / 12);
  return `${years}y ago`;
}

// Absolute timestamp for tables. Rendered on the server, so the time zone
// is pinned to UTC and labelled rather than guessing the viewer's.
const dateTimeFmt = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC",
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
});
const dateFmt = new Intl.DateTimeFormat("en-GB", {
  timeZone: "UTC",
  year: "numeric",
  month: "short",
  day: "numeric",
});

export function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : `${dateTimeFmt.format(d)} UTC`;
}

export function formatDate(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "—" : dateFmt.format(d);
}
