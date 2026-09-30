import { cookies } from "next/headers";

import { CommandMenu } from "@/components/command-menu";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { Header } from "@/components/layout/header";
import { SidebarProvider } from "@/components/ui/sidebar";
import { ViewerProvider } from "@/components/viewer-context";
import { getNavCounts } from "@/lib/queries-nav";
import { cn } from "@/lib/utils";
import { requireViewer } from "@/lib/viewer";

interface Props {
  children: React.ReactNode;
}

export default async function DashboardLayout({ children }: Props) {
  // Signed out, disabled, or still on a temporary password: redirected here,
  // before anything renders.
  const [cookieStore, viewer] = await Promise.all([cookies(), requireViewer()]);
  /** Matches client `sidebar.tsx`: cookie is `"true"` / `"false"`; treat missing as open. */
  const sidebarDefaultOpen = cookieStore.get("sidebar_state")?.value !== "false";

  const user = {
    name: viewer.name || viewer.username || viewer.email.split("@")[0] || viewer.email,
    email: viewer.email,
    role: viewer.role,
  };
  const counts = await getNavCounts(viewer.workspaceId);

  return (
    <ViewerProvider role={viewer.role}>
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
    </ViewerProvider>
  );
}
