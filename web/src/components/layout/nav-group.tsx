"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { cn } from "@/lib/utils";

import type { NavBadgeTone, NavGroup, NavItem } from "./types";

const BADGE_TONE: Record<NavBadgeTone, string> = {
  critical:
    "bg-danger/15 text-danger-fg peer-hover/menu-button:text-danger-fg peer-data-[active=true]/menu-button:text-danger-fg",
  warning:
    "bg-warning/15 text-warning-fg peer-hover/menu-button:text-warning-fg peer-data-[active=true]/menu-button:text-warning-fg",
};
const DOT_TONE: Record<NavBadgeTone, string> = { critical: "bg-danger", warning: "bg-warning" };

export function NavGroup({ title, items, navUrls }: NavGroup & { navUrls: string[] }) {
  const { setOpenMobile } = useSidebar();
  const pathname = usePathname();
  return (
    <SidebarGroup>
      {title && <SidebarGroupLabel>{title}</SidebarGroupLabel>}
      <SidebarMenu>
        {items.map((item) => (
          <SidebarMenuItem key={item.url}>
            <SidebarMenuButton
              asChild
              isActive={checkIsActive(pathname, item, navUrls)}
              tooltip={
                item.badge ? `${item.title} · ${item.badge.count} need attention` : item.title
              }
              className="relative"
            >
              <Link href={item.url} onClick={() => setOpenMobile(false)}>
                <item.icon />
                {item.badge && (
                  // The badge's stand-in when the sidebar is collapsed to icons.
                  <span
                    aria-hidden="true"
                    className={cn(
                      "absolute top-1 right-1 hidden size-2 rounded-full group-data-[collapsible=icon]:block",
                      DOT_TONE[item.badge.tone],
                    )}
                  />
                )}
                <span>
                  {item.title}
                  {item.badge && (
                    <span className="sr-only">, {item.badge.count} need attention</span>
                  )}
                </span>
              </Link>
            </SidebarMenuButton>
            {item.badge && (
              <SidebarMenuBadge
                aria-hidden="true"
                className={cn("rounded-full px-1.5", BADGE_TONE[item.badge.tone])}
              >
                {item.badge.count > 99 ? "99+" : item.badge.count}
              </SidebarMenuBadge>
            )}
          </SidebarMenuItem>
        ))}
      </SidebarMenu>
    </SidebarGroup>
  );
}

// navUrls (every url in the nav) turns on prefix matching: an item stays
// active on its sub-pages, e.g. /dashboard/reports/<id> keeps Reports
// active. An item whose url is a prefix of another nav url (Overview's
// /dashboard) only matches exactly, so it doesn't light up on every page.
export function checkIsActive(href: string, item: Pick<NavItem, "url">, navUrls?: string[]) {
  const currentPath = normalizePath(href);
  const itemPath = normalizePath(item.url);
  if (currentPath === itemPath) {
    return true;
  }

  const prefix = `${itemPath}/`;
  return (
    !!navUrls &&
    itemPath !== "/" &&
    currentPath.startsWith(prefix) &&
    !navUrls.some((url) => normalizePath(url).startsWith(prefix))
  );
}

function normalizePath(url: string): string {
  const [path] = url.split("?");
  return path.replace(/\/$/, "") || "/";
}
