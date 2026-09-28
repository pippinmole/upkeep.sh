"use client";

import {
  BellRing,
  Boxes,
  Container,
  LayoutDashboard,
  Monitor,
  Package,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import * as React from "react";

import { NavGroup } from "@/components/layout/nav-group";
import { NavSettings } from "@/components/layout/nav-settings";
import { NavUser } from "@/components/layout/nav-user";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@/components/ui/sidebar";

import type { NavGroup as NavGroupType, User } from "./types";

const SWARM_URL = "/dashboard/swarm";

export const navGroups: NavGroupType[] = [
  {
    title: "General",
    items: [
      { title: "Overview", url: "/dashboard", icon: LayoutDashboard },
      // Hosts are the machines, Agents the collectors (DOMAIN_MODEL.md
      // §3.1, §4, Q15); both can enroll an agent.
      { title: "Hosts", url: "/dashboard/hosts", icon: Monitor },
      { title: "Agents", url: "/dashboard/agents", icon: Server },
      { title: "Vulnerabilities", url: "/dashboard/vulnerabilities", icon: ShieldAlert },
      { title: "Packages", url: "/dashboard/packages", icon: Package },
      { title: "Images", url: "/dashboard/images", icon: Container },
      // In the sidebar only when a host is in a Swarm (AppSidebar
      // hasSwarm); the command menu always lists it.
      { title: "Swarm", url: SWARM_URL, icon: Boxes },
      { title: "Alerts", url: "/dashboard/alerts", icon: BellRing },
    ],
  },
];

interface Props extends React.ComponentProps<typeof Sidebar> {
  user: User;
  hasSwarm: boolean;
}

export function AppSidebar({ user, hasSwarm, ...props }: Props) {
  const groups = hasSwarm
    ? navGroups
    : navGroups.map((g) => ({ ...g, items: g.items.filter((i) => i.url !== SWARM_URL) }));
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-1.5">
          <div className="border-muted-foreground/25 flex aspect-square size-8 shrink-0 items-center justify-center rounded-lg border bg-transparent">
            <ShieldCheck className="size-4" />
          </div>
          <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
            <span className="truncate font-semibold">upkeep.sh</span>
            <span className="text-muted-foreground truncate text-xs">Monitoring</span>
          </div>
        </div>
      </SidebarHeader>
      <SidebarContent>
        {groups.map((group) => (
          <NavGroup key={group.title} {...group} />
        ))}
      </SidebarContent>
      <SidebarFooter>
        <NavSettings />
        <NavUser user={user} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
