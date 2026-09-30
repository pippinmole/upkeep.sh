// Parsing for the global search (command menu). Pure, so it runs in the
// browser (to skip requests the server would refuse) and in tests.
// Everything the user typed ends up as a bound SQL parameter, never
// interpolated.

export const MIN_QUERY_LENGTH = 2;
export const MAX_QUERY_LENGTH = 100;
// Groups that match through a trigram index (packages, vulnerabilities)
// need this many characters: below it the index can't help and the query
// would scan install-wide tables on every keystroke.
export const TRIGRAM_MIN_LENGTH = 3;
// Results per group.
export const GROUP_LIMIT = 5;

// The trimmed query with inner whitespace collapsed, capped in length, or
// null when it is too short to search.
export function normalizeQuery(raw: string | null | undefined): string | null {
  const q = (raw ?? "").trim().replace(/\s+/g, " ").slice(0, MAX_QUERY_LENGTH).trim();
  return q.length >= MIN_QUERY_LENGTH ? q : null;
}

// Escape LIKE / ILIKE wildcards so "%" and "_" match themselves. Postgres'
// default escape character is the backslash.
export function escapeLike(s: string): string {
  return s.replace(/[\\%_]/g, (c) => `\\${c}`);
}

// Advisory id shapes the vulnerability pages understand. A query that is
// exactly one of these is also looked up in the full feed, not only among
// the workspace's findings.
const EXACT_VULN_ID =
  /^(?:CVE-\d{4}-\d{4,}|GHSA(?:-[0-9a-z]{4}){3}|(?:USN|LSN)-\d+-\d+|(?:DSA|DLA)-\d+(?:-\d+)?|(?:DEBIAN|UBUNTU)-CVE-\d{4}-\d{4,}|(?:ALSA|RHSA|ALBA|ELSA)-\d{4}:\d+)$/i;

// The canonical spelling of an exact advisory id: upper case, except a
// GHSA id's tail, which is lower case. Null when q isn't one.
export function exactVulnId(q: string): string | null {
  const s = q.trim();
  if (!EXACT_VULN_ID.test(s)) return null;
  return /^ghsa-/i.test(s) ? `GHSA${s.slice(4).toLowerCase()}` : s.toUpperCase();
}

export type SearchTerms = {
  q: string; // normalized query, as typed
  lower: string; // lower-cased, for exact-match ranking
  contains: string; // ILIKE pattern: anywhere
  prefix: string; // ILIKE pattern: at the start
  vulnId: string | null; // exact advisory id, if q is one
};

export function searchTerms(raw: string | null | undefined): SearchTerms | null {
  const q = normalizeQuery(raw);
  if (!q) return null;
  const esc = escapeLike(q);
  return {
    q,
    lower: q.toLowerCase(),
    contains: `%${esc}%`,
    prefix: `${esc}%`,
    vulnId: exactVulnId(q),
  };
}
