// Display side of server/internal/severity. The Go package decides the
// bucket and sort key (findings.severity / severity_key); the dashboard
// only labels, filters and orders by what it wrote. Buckets are listed most
// urgent first, matching Go's order ("unknown" sits above low on purpose:
// an untriaged issue must not sink below a triaged low one).

export const SEVERITIES = ["critical", "high", "medium", "unknown", "low", "negligible"] as const;
export type Severity = (typeof SEVERITIES)[number];

export function isSeverity(s: string | null | undefined): s is Severity {
  return !!s && (SEVERITIES as readonly string[]).includes(s);
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  unknown: "Unknown",
  low: "Low",
  negligible: "Negligible",
};

export type SeverityCounts = Record<Severity, number>;

export function emptySeverityCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, unknown: 0, low: 0, negligible: 0 };
}

// "0.81422" -> "81.4%"; EPSS scores are probabilities (0..1).
export function formatEpss(score: number | null): string | null {
  if (score === null) return null;
  const pct = score * 100;
  return `${pct < 0.1 ? pct.toFixed(2) : pct.toFixed(1)}%`;
}

// Public advisory pages for the record ids the OSV sync stores. Unknown
// shapes get no link rather than a guessed one.
export function advisoryUrl(id: string): string | null {
  if (/^(DSA|DLA|DTSA)-\d+(-\d+)?$/.test(id)) {
    return `https://security-tracker.debian.org/tracker/${id}`;
  }
  let m = /^DEBIAN-(CVE-\d{4}-\d+)$/.exec(id);
  if (m) return `https://security-tracker.debian.org/tracker/${m[1]}`;
  if (/^(USN|LSN)-\d+-\d+$/.test(id)) return `https://ubuntu.com/security/notices/${id}`;
  m = /^UBUNTU-(CVE-\d{4}-\d+)$/.exec(id);
  if (m) return `https://ubuntu.com/security/${m[1]}`;
  if (/^CVE-\d{4}-\d+$/.test(id)) return `https://www.cve.org/CVERecord?id=${id}`;
  return null;
}

// vuln_key is a CVE id or an advisory id; both are short ASCII tokens.
// Anything else in a URL is rejected before it reaches SQL.
const VULN_KEY_RE = /^[A-Za-z0-9][A-Za-z0-9._:+-]{0,99}$/;

export function isVulnKey(s: string): boolean {
  return VULN_KEY_RE.test(s);
}
