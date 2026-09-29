"use client";

import { ShieldCheck } from "lucide-react";
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

import { navGroupsFor } from "./nav-config";
import type { NavCounts, User } from "./types";

interface Props extends React.ComponentProps<typeof Sidebar> {
  user: User;
  counts: NavCounts;
}

export function AppSidebar({ user, counts, ...props }: Props) {
  const groups = navGroupsFor(counts);
  const navUrls = groups.flatMap((g) => g.items.map((i) => i.url));
  return (
    <Sidebar collapsible="icon" {...props}>
      <SidebarHeader>
        <div className="flex items-center gap-2 px-2 py-1.5">
          <div className="border-muted-foreground/25 flex aspect-square size-8 shrink-0 items-center justify-center rounded-lg border bg-transparent">
            <ShieldCheck className="size-4" />
          </div>
          <div className="grid flex-1 text-left text-sm leading-tight group-data-[collapsible=icon]:hidden">
            <span className="truncate font-semibold">upkeep.sh</span>
            <span className="text-muted-foreground truncate text-xs">Estate security</span>
          </div>
        </div>
      </SidebarHeader>
      <SidebarContent>
        {groups.map((group, i) => (
          <NavGroup key={group.title ?? i} {...group} navUrls={navUrls} />
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
