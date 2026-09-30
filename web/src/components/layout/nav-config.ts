import {
  BellRing,
  Boxes,
  Container,
  FileChartColumn,
  LayoutDashboard,
  type LucideIcon,
  Package,
  RadioTower,
  Server,
  ShieldAlert,
} from "lucide-react";

import type { NavBadgeKey, NavBadgeTone, NavCounts, NavGroup } from "./types";

// The one nav tree, read by the sidebar and the command menu. Badges mean "needs action", never totals (docs/design/ux-overhaul.md).
export interface NavConfigItem {
  title: string;
  url: string;
  icon: LucideIcon;
  // Extra words the command menu matches on.
  keywords?: string[];
  badge?: { key: NavBadgeKey; tone: NavBadgeTone };
  // Shown only when a host is in a Swarm.
  swarmOnly?: boolean;
}

export interface NavConfigGroup {
  title?: string;
  items: NavConfigItem[];
}

export const navConfig: NavConfigGroup[] = [
  {
    items: [{ title: "Overview", url: "/dashboard", icon: LayoutDashboard }],
  },
  {
    title: "Security",
    items: [
      {
        title: "Vulnerabilities",
        url: "/dashboard/vulnerabilities",
        icon: ShieldAlert,
        keywords: ["cve", "kev", "advisories", "findings"],
        badge: { key: "vulnsUrgent", tone: "critical" },
      },
    ],
  },
  {
    title: "Estate",
    items: [
      // Hosts are the machines, Agents the collectors (DOMAIN_MODEL.md
      // §3.1, §4, Q15).
      {
        title: "Hosts",
        url: "/dashboard/hosts",
        icon: Server,
        keywords: ["servers", "machines", "vps"],
        badge: { key: "staleHosts", tone: "warning" },
      },
      {
        title: "Images",
        url: "/dashboard/images",
        icon: Container,
        keywords: ["docker", "containers", "registry"],
      },
      { title: "Packages", url: "/dashboard/packages", icon: Package },
      // Last, so nothing jumps when it appears.
      {
        title: "Swarm",
        url: "/dashboard/swarm",
        icon: Boxes,
        keywords: ["docker", "services", "cluster"],
        swarmOnly: true,
      },
    ],
  },
  {
    title: "Operations",
    items: [
      {
        title: "Alerts",
        url: "/dashboard/alerts",
        icon: BellRing,
        keywords: ["firing", "notifications", "delivery log"],
        badge: { key: "firingAlerts", tone: "warning" },
      },
      {
        title: "Reports",
        url: "/dashboard/reports",
        icon: FileChartColumn,
        keywords: ["schedules", "patch list"],
      },
      {
        title: "Agents",
        url: "/dashboard/agents",
        icon: RadioTower,
        keywords: ["collectors", "enroll", "install"],
        badge: { key: "staleAgents", tone: "warning" },
      },
    ],
  },
];

// The groups as shown: Swarm dropped when there is none.
export function visibleNavConfig(hasSwarm: boolean): NavConfigGroup[] {
  return navConfig.map((g) => ({
    ...g,
    items: g.items.filter((i) => hasSwarm || !i.swarmOnly),
  }));
}

// The sidebar's groups, with badge counts filled in (0 = no badge).
export function navGroupsFor(counts: NavCounts): NavGroup[] {
  return visibleNavConfig(counts.hasSwarm).map((g) => ({
    title: g.title,
    items: g.items.map(({ title, url, icon, badge }) => ({
      title,
      url,
      icon,
      badge:
        badge && counts[badge.key] > 0 ? { count: counts[badge.key], tone: badge.tone } : undefined,
    })),
  }));
}
