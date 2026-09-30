import { imageRepoHref, packageHref, vulnDetailHref } from "./links";
import type { SearchGroup } from "./sql";

// What the search endpoint returns, and how database rows become it. Pure,
// so the mapping is unit-tested and shared with the client (types only).

export type SearchResult = {
  id: string; // unique within its group
  title: string;
  subtitle?: string;
  // Short status words shown as a badge: "KEV", "archived", "revoked", …
  badge?: string;
  href: string;
};

export type SearchResponse = {
  query: string;
  groups: Record<SearchGroup, SearchResult[]>;
};

export const emptyGroups = (): Record<SearchGroup, SearchResult[]> => ({
  vulnerabilities: [],
  packages: [],
  images: [],
  containers: [],
  hosts: [],
  agents: [],
});

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const hostName = (hostname: string, label: string | null) =>
  label && label !== hostname ? `${label} (${hostname})` : hostname;

export type HostRow = {
  id: string;
  hostname: string;
  label: string | null;
  os_id: string | null;
  archived: boolean;
};
export function mapHost(r: HostRow): SearchResult {
  return {
    id: r.id,
    title: hostName(r.hostname, r.label),
    subtitle: r.os_id ?? undefined,
    badge: r.archived ? "archived" : undefined,
    href: `/dashboard/hosts/${encodeURIComponent(r.id)}`,
  };
}

export type AgentRow = {
  id: string;
  name: string;
  platform: string | null;
  revoked: boolean;
  hosts: string | number;
};
// There is no per-agent page: the Agents table, filtered to this name.
export function mapAgent(r: AgentRow): SearchResult {
  return {
    id: r.id,
    title: r.name,
    subtitle: [plural(Number(r.hosts), "host"), r.platform].filter(Boolean).join(" · "),
    badge: r.revoked ? "revoked" : undefined,
    href: `/dashboard/agents?q=${encodeURIComponent(r.name)}`,
  };
}

export type PackageRow = {
  name: string;
  ecosystems: string[];
  hosts: string | number;
  versions: string | number;
};
export function mapPackage(r: PackageRow): SearchResult {
  return {
    id: r.name,
    title: r.name,
    subtitle: [
      r.ecosystems.join(", "),
      plural(Number(r.hosts), "host"),
      plural(Number(r.versions), "version"),
    ]
      .filter(Boolean)
      .join(" · "),
    href: packageHref(r.name),
  };
}

export type ImageRow = { repo: string; hosts: string | number; tags: string[] | null };
export function mapImage(r: ImageRow): SearchResult {
  const tags = r.tags ?? [];
  return {
    id: r.repo,
    title: r.repo,
    subtitle: [plural(Number(r.hosts), "host"), tags.length ? `tags ${tags.join(", ")}` : null]
      .filter(Boolean)
      .join(" · "),
    href: imageRepoHref(r.repo),
  };
}

export type ContainerRow = {
  host_id: string;
  hostname: string;
  label: string | null;
  container_id: string;
  name: string;
  image: string | null;
  state: string | null;
};
// No per-container page: the host's Containers tab.
export function mapContainer(r: ContainerRow): SearchResult {
  return {
    id: `${r.host_id}/${r.container_id}`,
    title: r.name.replace(/^\//, ""),
    subtitle: [`on ${hostName(r.hostname, r.label)}`, r.image].filter(Boolean).join(" · "),
    badge: r.state && r.state !== "running" ? r.state : undefined,
    href: `/dashboard/hosts/${encodeURIComponent(r.host_id)}/containers`,
  };
}

// "open on 2 hosts · critical", "resolved", or "not found on your hosts".
function vulnStatus(openHosts: number, onHosts: boolean, severity: string | null): string[] {
  if (!onHosts) return ["not found on your hosts"];
  return [openHosts > 0 ? `open on ${plural(openHosts, "host")}` : "resolved", severity ?? ""];
}

export type VulnRow = {
  vuln_key: string;
  severity: string | null;
  is_kev: boolean;
  open_hosts: string | number;
};
export function mapVuln(r: VulnRow): SearchResult {
  return {
    id: r.vuln_key,
    title: r.vuln_key,
    subtitle: vulnStatus(Number(r.open_hosts), true, r.severity).filter(Boolean).join(" · "),
    badge: r.is_kev ? "KEV" : undefined,
    href: vulnDetailHref(r.vuln_key),
  };
}

export type FeedVulnRow = {
  vuln_key: string;
  via_advisory: string | null;
  is_kev: boolean;
  cvss_v3_score: number | null;
  description: string | null;
  severity: string | null;
  open_hosts: string | number;
  findings: string | number;
};
// An exact id looked up in the feed, with the workspace's status for it.
export function mapFeedVuln(r: FeedVulnRow): SearchResult {
  const onHosts = Number(r.findings) > 0;
  return {
    id: r.vuln_key,
    title: r.vuln_key,
    subtitle: [
      r.via_advisory ? `via ${r.via_advisory}` : null,
      ...vulnStatus(Number(r.open_hosts), onHosts, r.severity),
      !onHosts && r.cvss_v3_score != null ? `CVSS ${r.cvss_v3_score.toFixed(1)}` : null,
      !onHosts ? r.description : null,
    ]
      .filter(Boolean)
      .join(" · "),
    badge: r.is_kev ? "KEV" : undefined,
    href: vulnDetailHref(r.vuln_key),
  };
}

// An exact id's feed entries go first (they say which alias matched);
// then the workspace's substring matches, without repeats.
export function mergeVulns(
  workspace: SearchResult[],
  feed: SearchResult[],
  limit: number,
): SearchResult[] {
  const seen = new Set(feed.map((r) => r.id));
  return [...feed, ...workspace.filter((r) => !seen.has(r.id))].slice(0, limit);
}
