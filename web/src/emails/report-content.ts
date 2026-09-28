// What a report email says, independent of how it's drawn: report.tsx renders
// this as HTML and report-text.ts as the plain-text part, so both carry the
// same sections, wording and caps. Organised by action (docs/decisions/
// report-email-html.md): headline numbers, then what to patch and when, then
// what can't be patched, then coverage gaps (always shown: "all clear" with
// agents not reporting is false reassurance).
//
// Lists are cut to a few items so the HTML stays well under Gmail's ~102 KB
// clip limit; the rest is behind "…and N more, see the full report".

import type {
  ReportHostAction,
  ReportHostRef,
  ReportImageAction,
  ReportMetricChange,
  ReportMetricKey,
  ReportSnapshot,
  ReportTier,
} from "@/lib/report-snapshot";
import { formatEpss, SEVERITY_LABEL, type Severity } from "@/lib/severity";

// Items per section, then names within one item.
export const SECTION_CAP = 15;
export const CONVENIENT_CAP = 10;
export const ATTRIBUTION_CAP = 10;
const HOSTS_PER_ITEM = 8;
const CVES_PER_ITEM = 5;
const NAMES_PER_ITEM = 5;

export type Tone = "danger" | "warning" | "neutral";
export type Badge = { text: string; tone: Tone };

export type Item = {
  title: string;
  badges: Badge[];
  details: string[];
};

export type SectionId =
  | "patch_now"
  | "patch_this_week"
  | "images"
  | "when_convenient"
  | "reboots"
  | "no_fix"
  | "coverage";

export type Section = {
  id: SectionId;
  heading: string;
  /** One line under the heading saying what to do. */
  lead: string;
  /** Free text before the items (counts, notes). */
  notes: string[];
  items: Item[];
  /** Items left out by the cap. */
  more: number;
  /** Shown instead of items when there are none. */
  empty: string | null;
};

export type HeadlineRow = {
  key: ReportMetricKey;
  label: string;
  value: number;
  /** "+3 (+40%)", "no change"; null when there's nothing to compare with. */
  change: string | null;
};

export type ReportEmailModel = {
  title: string;
  /** Inbox preview line. */
  preheader: string;
  period: string;
  headline: HeadlineRow[];
  /** Comparison caveats and host attribution, under the numbers. */
  changeNotes: string[];
  sections: Section[];
  estate: string;
  reportUrl: string | null;
};

export const MORE_TEXT = "see the full report";

export function moreLine(n: number): string {
  return `…and ${n} more, ${MORE_TEXT}`;
}

const HEADLINE: { key: ReportMetricKey; label: string; noun: string }[] = [
  { key: "patch_now", label: "Patch now", noun: "to patch now" },
  { key: "patch_this_week", label: "Patch this week", noun: "to patch this week" },
  { key: "when_convenient", label: "When convenient", noun: "to patch when convenient" },
  { key: "images_to_update", label: "Images to update", noun: "images to update" },
  { key: "reboots_required", label: "Reboots required", noun: "reboots required" },
  { key: "no_fix_findings", label: "No fix available yet", noun: "findings with no fix" },
  { key: "total_open_findings", label: "Open findings", noun: "open findings" },
  { key: "opened_since_last", label: "Opened since last report", noun: "findings opened" },
  { key: "resolved_since_last", label: "Resolved since last report", noun: "findings resolved" },
  { key: "stale_agents", label: "Agents not reporting", noun: "agents not reporting" },
];

const TIER_LABEL: Record<ReportTier, string> = {
  patch_now: "Patch now",
  patch_this_week: "Patch this week",
  when_convenient: "When convenient",
};

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

// "a, b, c and 4 more"
function nameList(names: string[], cap: number): string {
  if (names.length <= cap) return names.join(", ");
  return `${names.slice(0, cap).join(", ")} and ${names.length - cap} more`;
}

function hostNames(hosts: ReportHostRef[]): string {
  return nameList(
    hosts.map((h) => h.name),
    HOSTS_PER_ITEM,
  );
}

// Dates in the schedule's time zone, which is what "Monday 07:00" meant to
// whoever set it up. An unknown zone (shouldn't happen: Next.js validates
// it) falls back to UTC rather than failing the render.
function formatters(timeZone: string) {
  const make = (tz: string) => ({
    date: new Intl.DateTimeFormat("en-GB", {
      timeZone: tz,
      year: "numeric",
      month: "short",
      day: "numeric",
    }),
    dateTime: new Intl.DateTimeFormat("en-GB", {
      timeZone: tz,
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      timeZoneName: "short",
    }),
  });
  try {
    return make(timeZone);
  } catch {
    return make("UTC");
  }
}

type Fmt = ReturnType<typeof formatters>;

function fmt(f: Intl.DateTimeFormat, iso: string | null): string {
  if (!iso) return "unknown";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "unknown" : f.format(d);
}

export function formatChange(c: ReportMetricChange): string {
  if (c.delta === 0) return "no change";
  const sign = c.delta > 0 ? "+" : "−";
  const abs = `${sign}${Math.abs(c.delta)}`;
  if (c.percent === null) return abs;
  const pctSign = c.percent > 0 ? "+" : c.percent < 0 ? "−" : "";
  return `${abs} (${pctSign}${Math.abs(c.percent)}%)`;
}

function severityBadge(s: Severity): Badge {
  const tone: Tone = s === "critical" || s === "high" ? "danger" : "neutral";
  return { text: SEVERITY_LABEL[s], tone };
}

function riskBadges(a: {
  kev: boolean;
  worst_severity: Severity;
  max_epss: number | null;
}): Badge[] {
  const badges: Badge[] = [];
  if (a.kev) badges.push({ text: "KEV", tone: "danger" });
  badges.push(severityBadge(a.worst_severity));
  const epss = formatEpss(a.max_epss);
  if (epss) badges.push({ text: `EPSS ${epss}`, tone: "neutral" });
  return badges;
}

function hostActionItem(a: ReportHostAction, f: Fmt): Item {
  const badges = riskBadges(a);
  if (a.requires_pro) badges.push({ text: "Ubuntu Pro", tone: "warning" });
  const binaries =
    a.binary_packages.length > 0 &&
    !(a.binary_packages.length === 1 && a.binary_packages[0] === a.package)
      ? `Installed as ${nameList(a.binary_packages, NAMES_PER_ITEM)}`
      : null;
  return {
    title: `${a.package} → ${a.fixed_version}`,
    badges,
    details: [
      `${plural(a.host_count, "host", "hosts")}: ${hostNames(a.hosts)}`,
      `Closes ${plural(a.cve_count, "vulnerability", "vulnerabilities")}: ${nameList(a.cves, CVES_PER_ITEM)}`,
      ...(binaries ? [binaries] : []),
      `Open since ${fmt(f.date, a.oldest_open_at)}`,
    ],
  };
}

function platform(i: { os: string; arch: string; variant: string }): string {
  return [i.os, i.arch, i.variant].filter(Boolean).join("/");
}

// Repo tags, else a short image id.
function imageName(i: { image_id: string; image_refs: string[] }): string {
  if (i.image_refs.length > 0) return nameList(i.image_refs, 3);
  return i.image_id.replace(/^sha256:/, "").slice(0, 12);
}

function imageActionItem(a: ReportImageAction, f: Fmt): Item {
  const hosts = a.hosts.length;
  return {
    title: `${imageName(a)} (${platform(a)})`,
    badges: [
      { text: TIER_LABEL[a.tier], tone: a.tier === "patch_now" ? "danger" : "neutral" },
      ...riskBadges(a),
    ],
    details: [
      `${a.fixable_findings} of ${plural(a.open_findings, "finding", "findings")} fixed by re-pulling or rebuilding`,
      `${plural(a.containers.length, "container", "containers")} on ${plural(hosts, "host", "hosts")}: ${nameList(a.containers, NAMES_PER_ITEM)} on ${hostNames(a.hosts)}`,
      `Open since ${fmt(f.date, a.oldest_open_at)}`,
    ],
  };
}

function capped<T>(list: T[], cap: number, toItem: (t: T) => Item) {
  return { items: list.slice(0, cap).map(toItem), more: Math.max(0, list.length - cap) };
}

function hostActionSection(
  s: ReportSnapshot,
  f: Fmt,
  tier: ReportTier,
  id: SectionId,
  lead: string,
  cap: number,
  empty: string,
): Section {
  const actions = s.host_actions.filter((a) => a.tier === tier);
  const images = s.image_actions.filter((a) => a.tier === tier).length;
  const notes =
    images > 0
      ? [`Plus ${plural(images, "image", "images")} in this tier, under Images to update.`]
      : [];
  return {
    id,
    heading: TIER_LABEL[tier],
    lead,
    notes,
    ...capped(actions, cap, (a) => hostActionItem(a, f)),
    empty: actions.length === 0 ? empty : null,
  };
}

// "db-1 was added since the last report: 1 of the 1 to patch now, 9 of the
// 42 open findings." Archived hosts are compared with the previous report,
// which is where their share was counted.
function attribution(s: ReportSnapshot): string[] {
  const c = s.changes;
  if (!c) return [];
  const lines: string[] = [];
  const share = (
    contribution: Partial<Record<ReportMetricKey, number>>,
    total: (key: ReportMetricKey) => number | null,
  ) =>
    HEADLINE.flatMap(({ key, noun }) => {
      const n = contribution[key] ?? 0;
      if (n <= 0) return [];
      const of = total(key);
      return [of === null ? `${n} ${noun}` : `${n} of the ${of} ${noun}`];
    });
  const hosts = [
    ...c.hosts_added.map((h) => ({ h, added: true })),
    ...c.hosts_archived.map((h) => ({ h, added: false })),
  ];
  for (const { h, added } of hosts.slice(0, ATTRIBUTION_CAP)) {
    const parts = added
      ? share(h.contribution, (k) => s.headline[k])
      : share(h.contribution, (k) => c.metrics[k]?.previous ?? null);
    const what = added ? "was added since the last report" : "was archived since the last report";
    lines.push(
      parts.length > 0
        ? `${h.name} ${what}; it ${added ? "accounts for" : "had"} ${parts.join(", ")}.`
        : `${h.name} ${what}.`,
    );
  }
  if (hosts.length > ATTRIBUTION_CAP) {
    lines.push(
      `…and ${hosts.length - ATTRIBUTION_CAP} more hosts added or archived, ${MORE_TEXT}.`,
    );
  }
  return lines;
}

function coverageSection(s: ReportSnapshot, f: Fmt): Section {
  const cov = s.coverage;
  const items: Item[] = [
    ...cov.stale_agents.map((a) => ({
      title: `Agent ${a.name} not reporting`,
      badges: [{ text: "Stale", tone: "warning" as Tone }],
      details: [
        a.last_seen_at ? `Last seen ${fmt(f.dateTime, a.last_seen_at)}` : "Never seen",
        a.hosts.length > 0 ? `Hosts: ${hostNames(a.hosts)}` : "No hosts enrolled",
      ],
    })),
    ...cov.hosts_without_docker.map((h) => ({
      title: `${h.name}: no Docker collection`,
      badges: [],
      details: ["Containers and images on this host aren't checked"],
    })),
    ...cov.images_not_scored.map((i) => ({
      title: `${imageName(i)} (${platform(i)}) not scored`,
      badges: [],
      details: [
        i.status === "pending"
          ? "Package list received, not scored yet"
          : i.status === "none"
            ? "No package list"
            : i.status === "unavailable"
              ? "Package list unavailable"
              : "Package list failed",
      ],
    })),
  ];
  const n = items.length;
  const counts = [
    plural(cov.stale_agents.length, "agent not reporting", "agents not reporting"),
    plural(
      cov.hosts_without_docker.length,
      "host without Docker collection",
      "hosts without Docker collection",
    ),
    plural(cov.images_not_scored.length, "image not scored", "images not scored"),
  ];
  return {
    id: "coverage",
    heading: "Coverage gaps",
    lead: "What this report can't see. Numbers above may be missing findings from these.",
    notes: n > 0 ? [`${counts.join(", ")}.`] : [],
    items: items.slice(0, SECTION_CAP),
    more: Math.max(0, n - SECTION_CAP),
    empty:
      n === 0
        ? "No coverage gaps: every agent is reporting, every host has Docker collection and every image is scored."
        : null,
  };
}

export function reportEmailModel(s: ReportSnapshot, reportUrl: string | null): ReportEmailModel {
  const f = formatters(s.schedule.timezone);
  const c = s.changes;

  const headline: HeadlineRow[] = HEADLINE.map(({ key, label }) => {
    const m = c?.metrics[key];
    return { key, label, value: s.headline[key], change: m ? formatChange(m) : null };
  });

  const changeNotes: string[] = [];
  if (c) {
    changeNotes.push(
      `Changes are since the last report, ${fmt(f.dateTime, c.previous_generated_at)}.`,
    );
    if (!c.comparable) {
      changeNotes.push(
        "How actions are ranked into tiers changed since the last report, so tier numbers aren't compared.",
      );
    }
    changeNotes.push(...attribution(s));
  }

  const nf = s.no_fix;
  const noFix: Section = {
    id: "no_fix",
    heading: "No fix available yet",
    lead: "Tracked, nothing to do until the distribution or image publishes a fix.",
    notes:
      nf.findings > 0
        ? [
            `${plural(nf.findings, "open finding", "open findings")} with no fix: ${nf.host_package_findings} in host packages, ${nf.image_findings} in images. Worst severity: ${nf.worst_severity ? SEVERITY_LABEL[nf.worst_severity] : "unknown"}.`,
            ...(nf.kev_findings > 0
              ? [
                  `${plural(nf.kev_findings, "is", "are")} on the CISA KEV list (exploited in the wild).`,
                ]
              : []),
          ]
        : [],
    items: [],
    more: 0,
    empty: nf.findings === 0 ? "None." : null,
  };

  const sections: Section[] = [
    hostActionSection(
      s,
      f,
      "patch_now",
      "patch_now",
      "Known exploited (CISA KEV). Upgrade these packages now.",
      SECTION_CAP,
      "Nothing urgent.",
    ),
    hostActionSection(
      s,
      f,
      "patch_this_week",
      "patch_this_week",
      "Critical or high severity with a fix, or likely to be exploited (high EPSS).",
      SECTION_CAP,
      "Nothing to patch this week.",
    ),
    {
      id: "images",
      heading: "Images to update",
      lead: "Re-pull or rebuild these images, then recreate their containers.",
      notes: [],
      ...capped(s.image_actions, SECTION_CAP, (a) => imageActionItem(a, f)),
      empty: s.image_actions.length === 0 ? "No images to update." : null,
    },
    hostActionSection(
      s,
      f,
      "when_convenient",
      "when_convenient",
      "Everything else with a fix.",
      CONVENIENT_CAP,
      "Nothing else to patch.",
    ),
    {
      id: "reboots",
      heading: "Reboots required",
      lead: "Updates are installed but not in use until these hosts restart.",
      notes: [],
      ...capped(s.reboots_required, SECTION_CAP, (r) => ({
        title: r.host_name,
        badges: [],
        details: [
          ...(r.packages.length > 0 ? [`For ${nameList(r.packages, NAMES_PER_ITEM)}`] : []),
          ...(r.since ? [`Since ${fmt(f.date, r.since)}`] : []),
        ],
      })),
      empty: s.reboots_required.length === 0 ? "No reboots pending." : null,
    },
    noFix,
    coverageSection(s, f),
  ];

  const e = s.estate;
  return {
    title: s.schedule.name,
    preheader: `${s.headline.total_open_findings} open findings across ${plural(e.hosts, "host", "hosts")}.`,
    period: `${fmt(f.dateTime, s.period.start)} to ${fmt(f.dateTime, s.period.end)}`,
    headline,
    changeNotes,
    sections,
    estate: `${plural(e.hosts, "host", "hosts")}, ${plural(e.containers, "container", "containers")} and ${plural(e.images, "image", "images")} (archived hosts excluded).`,
    reportUrl,
  };
}
