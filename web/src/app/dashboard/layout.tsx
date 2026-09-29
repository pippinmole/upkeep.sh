import { cookies } from "next/headers";

import { CommandMenu } from "@/components/command-menu";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { Header } from "@/components/layout/header";
import type { NavCounts } from "@/components/layout/types";
import { SidebarProvider } from "@/components/ui/sidebar";
import { auth } from "@/lib/auth";
import { getNavCounts } from "@/lib/queries-nav";
import { cn } from "@/lib/utils";

const NO_COUNTS: NavCounts = {
  vulnsUrgent: 0,
  staleHosts: 0,
  staleAgents: 0,
  failedDeliveries: 0,
  hasSwarm: false,
};

interface Props {
  children: React.ReactNode;
}

export default async function DashboardLayout({ children }: Props) {
  const [cookieStore, session] = await Promise.all([cookies(), auth()]);
  /** Matches client `sidebar.tsx`: cookie is `"true"` / `"false"`; treat missing as open. */
  const sidebarDefaultOpen = cookieStore.get("sidebar_state")?.value !== "false";

  const email = session?.user?.email ?? "unknown@example.com";
  const user = { name: email.split("@")[0] ?? email, email };
  const counts = session?.user?.id ? await getNavCounts(session.user.id) : NO_COUNTS;

  return (
    <div className="border-grid flex flex-1 flex-col">
      <SidebarProvider defaultOpen={sidebarDefaultOpen}>
        <AppSidebar user={user} counts={counts} />
        <div
          id="content"
          className={cn(
            "flex h-full w-full min-w-0 flex-col",
            "has-[div[data-layout=fixed]]:h-svh",
            "group-data-[scroll-locked=1]/body:h-full",
            "has-[data-layout=fixed]:group-data-[scroll-locked=1]/body:h-svh",
          )}
        >
          <Header />
          {children}
        </div>
        <CommandMenu hasSwarm={counts.hasSwarm} />
      </SidebarProvider>
    </div>
  );
}
