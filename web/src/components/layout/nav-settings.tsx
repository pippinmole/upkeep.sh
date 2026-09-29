"use client";

import { Settings } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";

import { checkIsActive } from "./nav-group";
import { SETTINGS_URL, settingsSections } from "./settings-sections";

// Settings sits in the sidebar footer, just above the user menu, rather
// than in the main nav list. It opens the first section directly.
export function NavSettings() {
  const { setOpenMobile } = useSidebar();
  const pathname = usePathname();
  const active = checkIsActive(pathname, { url: SETTINGS_URL }, [SETTINGS_URL]);
  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <SidebarMenuButton asChild isActive={active} tooltip="Settings">
          <Link href={settingsSections[0].url} onClick={() => setOpenMobile(false)}>
            <Settings />
            <span>Settings</span>
          </Link>
        </SidebarMenuButton>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
