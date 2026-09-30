import { activeHost } from "../owner";
import { plural } from "../rank";
import type { AttentionItem, AttentionProvider } from "../types";

// Host package vulnerabilities to patch first: known-exploited ones (KEV),
// and critical ones a package upgrade from the distro fixes today.
// Findings are counted, as on the Overview's metric cards and the fix
// availability rows, so the numbers agree.

type Row = {
  kev: string;
  kev_hosts: string;
  kev_fixable: string;
  critical_fixable: string;
  critical_fixable_hosts: string;
};

export type VulnCounts = {
  kev: number;
  kevHosts: number;
  kevFixable: number;
  criticalFixable: number;
  criticalFixableHosts: number;
};

// findings_host_open_rank_idx per host; only open KEV or critical findings.
const SQL = `
  SELECT count(*) FILTER (WHERE f.is_kev) AS kev,
         count(DISTINCT f.host_id) FILTER (WHERE f.is_kev) AS kev_hosts,
         count(*) FILTER (WHERE f.is_kev AND f.fix_channel = 'standard') AS kev_fixable,
         count(*) FILTER (WHERE f.severity = 'critical' AND f.fix_channel = 'standard')
           AS critical_fixable,
         count(DISTINCT f.host_id) FILTER (WHERE f.severity = 'critical' AND f.fix_channel = 'standard')
           AS critical_fixable_hosts
  FROM hosts h
  JOIN findings f ON f.host_id = h.id
  WHERE ${activeHost("h")}
    AND f.kind = 'vulnerable_package' AND f.status = 'open'
    AND (f.is_kev OR f.severity = 'critical')`;

export const vulnerabilities: AttentionProvider<VulnCounts> = {
  key: "vulns",
  load: async (ctx) => {
    const [r] = await ctx.query<Row>(SQL);
    return {
      kev: Number(r?.kev ?? 0),
      kevHosts: Number(r?.kev_hosts ?? 0),
      kevFixable: Number(r?.kev_fixable ?? 0),
      criticalFixable: Number(r?.critical_fixable ?? 0),
      criticalFixableHosts: Number(r?.critical_fixable_hosts ?? 0),
    };
  },
  map: (v) => {
    const items: AttentionItem[] = [];
    if (v.kev > 0) {
      items.push({
        key: "kev",
        severity: "critical",
        tone: "kev",
        icon: "kev",
        title: `Known-exploited vulnerabilities on ${plural(v.kevHosts, "host", "hosts")}`,
        subject:
          v.kevFixable > 0
            ? `${v.kevFixable.toLocaleString("en-US")} with a fix available`
            : "No fix available yet",
        why: "Listed in CISA's KEV catalog: attackers use these now, so patch them first.",
        count: v.kev,
        href: "/dashboard/vulnerabilities?kev=1",
      });
    }
    if (v.criticalFixable > 0) {
      items.push({
        key: "critical-fixable",
        severity: "high",
        tone: "danger",
        icon: "vuln",
        title: "Critical vulnerabilities with a fix available",
        subject: `On ${plural(v.criticalFixableHosts, "host", "hosts")}`,
        why: "A package upgrade from the distribution fixes them today.",
        count: v.criticalFixable,
        href: "/dashboard/vulnerabilities?severity=critical&fix=available",
      });
    }
    return items;
  },
};
