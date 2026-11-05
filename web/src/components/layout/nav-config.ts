import {
  BellRing,
  Boxes,
  Container,
  FileChartColumn,
  LayoutDashboard,
  type LucideIcon,
  Package,
  Settings,
  ShieldAlert,
} from "lucide-react";

// The top bar's tabs, read by the top bar and the command menu.
export type NavTab = {
  title: string;
  url: string;
  icon: LucideIcon;
  // Extra words the command menu matches on.
  keywords?: string[];
  // Path prefixes that light the tab.
  match: string[];
};

export const tabs: NavTab[] = [
  {
    title: "Machines",
    url: "/dashboard",
    icon: LayoutDashboard,
    // Never shown; "servers" only helps people who type it find the tab.
    keywords: ["hosts", "servers", "vps", "overview"],
    match: ["/dashboard", "/dashboard/hosts"],
  },
  {
    title: "Vulnerabilities",
    url: "/dashboard/vulnerabilities",
    icon: ShieldAlert,
    keywords: ["cve", "kev", "advisories", "findings"],
    match: ["/dashboard/vulnerabilities"],
  },
  {
    title: "Images",
    url: "/dashboard/images",
    icon: Container,
    keywords: ["docker", "containers", "registry"],
    match: ["/dashboard/images"],
  },
  {
    title: "Alerts",
    url: "/dashboard/alerts",
    icon: BellRing,
    keywords: ["firing", "notifications", "delivery log"],
    match: ["/dashboard/alerts"],
  },
  {
    title: "Reports",
    url: "/dashboard/reports",
    icon: FileChartColumn,
    keywords: ["schedules", "patch list"],
    match: ["/dashboard/reports"],
  },
  {
    title: "Settings",
    url: "/dashboard/settings",
    icon: Settings,
    match: ["/dashboard/settings", "/dashboard/agents"],
  },
];

// Reachable from the command menu only. Agents is a Settings section
// (settings-sections.ts), so the menu lists it there.
export const moreLinks: (NavTab & { swarmOnly?: boolean })[] = [
  {
    title: "Packages",
    url: "/dashboard/packages",
    icon: Package,
    match: ["/dashboard/packages"],
  },
  {
    title: "Swarm",
    url: "/dashboard/swarm",
    icon: Boxes,
    keywords: ["docker", "services", "cluster"],
    match: ["/dashboard/swarm"],
    swarmOnly: true,
  },
];

// A prefix matches the path itself or anything beneath it; "/dashboard" is
// the home page, so it matches only exactly.
export function isTabActive(pathname: string, tab: NavTab): boolean {
  return tab.match.some((prefix) =>
    prefix === "/dashboard"
      ? pathname === prefix
      : pathname === prefix || pathname.startsWith(prefix + "/"),
  );
}
