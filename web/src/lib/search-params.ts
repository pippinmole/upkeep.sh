// Parsing for server-driven table state in URL search params
// (DOMAIN_MODEL.md §3, Q11). Everything here is untrusted input: values end
// up as bound SQL parameters, never interpolated.

export type SearchParams = Record<string, string | string[] | undefined>;

export function param(sp: SearchParams, key: string): string | null {
  const v = sp[key];
  const s = (Array.isArray(v) ? v[0] : v)?.trim();
  return s ? s.slice(0, 200) : null;
}

export function pageParam(sp: SearchParams): number {
  const n = Number.parseInt(param(sp, "page") ?? "1", 10);
  return Number.isFinite(n) && n >= 1 && n <= 100_000 ? n : 1;
}

// An "all" sentinel is used by selects (Radix Select can't have an empty
// item value).
export function filterParam(sp: SearchParams, key: string): string | null {
  const v = param(sp, key);
  return v && v !== "all" ? v : null;
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TS_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/;

// Point-in-time parameter. Accepts a date (YYYY-MM-DD, meaning the end of
// that day in UTC, so the day's changes are included) or an exact UTC
// timestamp with up to microsecond precision (history links use the exact
// range boundary). Returned as a string for Postgres to parse as
// timestamptz, so microseconds survive (JS Date would truncate them).
export function parseAt(raw: string | null): string | null {
  if (!raw) return null;
  if (DATE_RE.test(raw)) {
    if (Number.isNaN(Date.parse(`${raw}T00:00:00Z`))) return null;
    return `${raw}T23:59:59.999999Z`;
  }
  if (TS_RE.test(raw) && !Number.isNaN(Date.parse(raw))) return raw;
  return null;
}

// Build a query string from the current params with overrides applied.
// null/"" removes a key.
export function withParams(
  sp: SearchParams,
  overrides: Record<string, string | number | null>,
): string {
  const out = new URLSearchParams();
  for (const [k, v] of Object.entries(sp)) {
    const s = Array.isArray(v) ? v[0] : v;
    if (s) out.set(k, s);
  }
  for (const [k, v] of Object.entries(overrides)) {
    if (v === null || v === "") out.delete(k);
    else out.set(k, String(v));
  }
  const qs = out.toString();
  return qs ? `?${qs}` : "";
}
