// The stored report snapshot (reports.snapshot): a hand-written mirror of
// server/internal/reports/snapshot.go, which is the source of truth and
// documents each field. Keep the two in step; the fixture
// report-snapshot.example.json is round-tripped through the Go types by
// `go test ./internal/reports` and type-checked against these types by
// report-snapshot.check.ts (`bunx tsc --noEmit`).
//
// Conventions (as in Go): lists are complete and never null; optional
// scalars are null, never missing; timestamps are RFC 3339 UTC strings;
// severities are Severity names; no URLs (build links at render time).
// Hosts are named as the dashboard names them (label, else hostname).

import type { Severity } from "@/lib/severity";

/** reports.RankingVersion when this file was written. */
export const REPORT_RANKING_VERSION = 1;
/** reports.SchemaVersion when this file was written. */
export const REPORT_SCHEMA_VERSION = 1;

export type ReportTier = "patch_now" | "patch_this_week" | "when_convenient";
export type ReportTrigger = "scheduled" | "manual";
export type ReportCadence = "weekly" | "monthly";

/** RFC 3339 timestamp in UTC. */
type Timestamp = string;

export type ReportSnapshot = {
  schema_version: number;
  /** Tier definitions used; comparison is suppressed across versions. */
  ranking_version: number;
  generated_at: Timestamp;
  /** What the "since last report" numbers cover (= reports.period_start / period_end). */
  period: { start: Timestamp; end: Timestamp };
  trigger: ReportTrigger;
  /** The schedule as it was when the report was built. */
  schedule: { id: string; name: string; cadence: ReportCadence; timezone: string };
  /** Non-archived hosts, their current containers, the distinct images those use. */
  estate: { hosts: number; containers: number; images: number };
  headline: ReportHeadline;
  /** Most urgent first. */
  host_actions: ReportHostAction[];
  /** Most urgent first. */
  image_actions: ReportImageAction[];
  reboots_required: ReportReboot[];
  no_fix: ReportNoFix;
  /** Always present: "all clear" with agents not reporting is false reassurance. */
  coverage: ReportCoverage;
  /** Per-host counts, for attributing changes. */
  hosts: ReportHostSummary[];
  /** Comparison with the schedule's previous report; null when there is none. */
  changes: ReportChanges | null;
};

/** Top-line numbers. Its keys are the metric keys of `changes`. */
export type ReportHeadline = {
  /** Action lines per tier, host packages and images together. */
  patch_now: number;
  patch_this_week: number;
  when_convenient: number;
  /** Image action lines (all tiers). */
  images_to_update: number;
  reboots_required: number;
  no_fix_findings: number;
  /** Open findings of both kinds, with or without a fix. */
  total_open_findings: number;
  /** Findings opened (or reopened) / resolved within `period`. */
  opened_since_last: number;
  resolved_since_last: number;
  stale_agents: number;
};

export type ReportMetricKey = keyof ReportHeadline;

export type ReportHostRef = { id: string; name: string };

/** One host-package upgrade: open findings grouped by (source package, fixed version). */
export type ReportHostAction = {
  tier: ReportTier;
  /** Source package. */
  package: string;
  /** Installed binary packages built from it, across the hosts. */
  binary_packages: string[];
  /** The highest version any of its CVEs needs. */
  fixed_version: string;
  fix_channel: "standard" | "ubuntu-pro";
  requires_pro: boolean;
  kev: boolean;
  worst_severity: Severity;
  max_epss: number | null;
  /** Vulnerability keys closed (CVE ids where there is one), sorted. */
  cves: string[];
  cve_count: number;
  hosts: ReportHostRef[];
  host_count: number;
  oldest_open_at: Timestamp;
};

/** One image to re-pull or rebuild, by image key (image_id, os, arch, variant). */
export type ReportImageAction = {
  tier: ReportTier;
  image_id: string;
  /** Repo tags (digests when untagged). */
  image_refs: string[];
  os: string;
  arch: string;
  /** "" when the platform has none. */
  variant: string;
  kev: boolean;
  worst_severity: Severity;
  max_epss: number | null;
  open_findings: number;
  /** Findings with a fix in the standard channel. */
  fixable_findings: number;
  /** Container names, across hosts. */
  containers: string[];
  hosts: ReportHostRef[];
  oldest_open_at: Timestamp;
};

export type ReportReboot = {
  host_id: string;
  host_name: string;
  /** Packages that asked for the reboot. */
  packages: string[];
  /** Null when unknown. */
  since: Timestamp | null;
};

/** Open findings with no fix yet: tracked, nothing to do. */
export type ReportNoFix = {
  findings: number;
  kev_findings: number;
  /** Null when `findings` is 0. */
  worst_severity: Severity | null;
  host_package_findings: number;
  image_findings: number;
};

export type ReportCoverage = {
  stale_agents: {
    agent_id: string;
    name: string;
    /** Null = never seen. */
    last_seen_at: Timestamp | null;
    hosts: ReportHostRef[];
  }[];
  hosts_without_docker: ReportHostRef[];
  images_not_scored: {
    image_id: string;
    image_refs: string[];
    os: string;
    arch: string;
    variant: string;
    /** image_scores.list_status, or "pending" for an ok list not scored yet. */
    status: "none" | "unavailable" | "error" | "pending";
  }[];
};

/** One host's share of the report; action counts are the action lines that include it. */
export type ReportHostSummary = {
  id: string;
  name: string;
  patch_now: number;
  patch_this_week: number;
  when_convenient: number;
  images_to_update: number;
  reboot_required: boolean;
  no_fix_findings: number;
  total_open_findings: number;
};

export type ReportChanges = {
  previous_report_id: string;
  previous_generated_at: Timestamp;
  /** False when the previous report used another ranking version; `metrics`
   * then omits every key whose definition depends on the ranking. */
  comparable: boolean;
  metrics: Partial<Record<ReportMetricKey, ReportMetricChange>>;
  /** Hosts in this report and not the previous one, and the reverse. */
  hosts_added: ReportHostChange[];
  hosts_archived: ReportHostChange[];
};

export type ReportMetricChange = {
  previous: number;
  current: number;
  /** current - previous */
  delta: number;
  /** delta / previous * 100, one decimal; null when previous < 10. */
  percent: number | null;
};

export type ReportHostChange = {
  id: string;
  name: string;
  /** The host's share of each metric it has a share of. */
  contribution: Partial<Record<ReportMetricKey, number>>;
};
