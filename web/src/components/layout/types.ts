import type { LucideIcon } from "lucide-react";

import type { Role } from "@/lib/roles";

interface User {
  name: string;
  email: string;
  role: Role;
}

// "Needs action" counts behind the nav badges (lib/queries-nav.ts), and
// whether the Swarm item shows at all.
interface NavCounts {
  vulnsUrgent: number;
  staleHosts: number;
  staleAgents: number;
  firingAlerts: number;
  hasSwarm: boolean;
}

type NavBadgeKey = Exclude<keyof NavCounts, "hasSwarm">;
type NavBadgeTone = "critical" | "warning";

interface NavItem {
  title: string;
  url: string;
  icon: LucideIcon;
  badge?: { count: number; tone: NavBadgeTone };
}

interface NavGroup {
  // Omitted for the top group (Overview), which has no label.
  title?: string;
  items: NavItem[];
}

export type { NavBadgeKey, NavBadgeTone, NavCounts, NavGroup, NavItem, User };
