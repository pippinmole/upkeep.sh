"use client";

import { LayoutDashboard, Server, ShieldCheck } from "lucide-react";
import * as React from "react";

import { NavGroup } from "@/components/layout/nav-group";
import { NavUser } from "@/components/layout/nav-user";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarRail,
} from "@/components/ui/sidebar";

import type { NavGroup as NavGroupType, User } from "./types";

export const navGroups: NavGroupType[] = [
  {
    title: "General",
    items: [
      { title: "Overview", url: "/dashboard", icon: LayoutDashboard },
      { title: "Agents", url: "/dashboard/agents", icon: Server },
    ],
  },
];

interface Props extends React.ComponentProps<typeof Sidebar> {
  user: User;
}

export function AppSidebar({ user, ...props }: Props) {
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-1.5">
          <div className="border-muted-foreground/25 flex aspect-square size-8 shrink-0 items-center justify-center rounded-lg border bg-transparent">
            <ShieldCheck className="size-4" />
          </div>
          <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
            <span className="truncate font-semibold">Security Whatnot</span>
            <span className="text-muted-foreground truncate text-xs">
              Monitoring
            </span>
          </div>
        </div>
      </SidebarHeader>
      <SidebarContent>
        {navGroups.map((group) => (
          <NavGroup key={group.title} {...group} />
        ))}
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={user} />
      </SidebarFooter>
      <SidebarRail />
    </Sidebar>
  );
}
