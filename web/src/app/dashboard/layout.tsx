import { cookies } from "next/headers";

import { AppSidebar } from "@/components/layout/app-sidebar";
import { Header } from "@/components/layout/header";
import { SidebarProvider } from "@/components/ui/sidebar";
import { auth } from "@/lib/auth";
import { cn } from "@/lib/utils";

interface Props {
  children: React.ReactNode;
}

export default async function DashboardLayout({ children }: Props) {
  const [cookieStore, session] = await Promise.all([cookies(), auth()]);
  /** Matches client `sidebar.tsx`: cookie is `"true"` / `"false"`; treat missing as open. */
  const sidebarDefaultOpen =
    cookieStore.get("sidebar_state")?.value !== "false";

  const email = session?.user?.email ?? "unknown@example.com";
  const user = { name: email.split("@")[0] ?? email, email };

  return (
    <div className="border-grid flex flex-1 flex-col">
      <SidebarProvider defaultOpen={sidebarDefaultOpen}>
        <AppSidebar user={user} />
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
      </SidebarProvider>
    </div>
  );
}
