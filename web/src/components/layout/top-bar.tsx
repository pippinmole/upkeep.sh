import Link from "next/link";

import { Search } from "@/components/search";

import { TopBarTabs } from "./top-bar-tabs";
import type { TopBarData, User } from "./types";
import { UserMenu } from "./user-menu";

// The dark bar across every dashboard page: wordmark and workspace, the
// tabs, then search, firing alerts and the user menu. Below md the tabs
// wrap onto a second row (order-last + basis-full).
export function TopBar({ data, user }: { data: TopBarData; user: User }) {
  return (
    <header className="bg-topbar text-topbar-foreground sticky top-0 z-30 flex flex-wrap items-center gap-x-4 px-4 sm:px-6">
      <div className="flex h-12 min-w-0 items-center gap-2 text-sm">
        <Link
          href="/dashboard"
          className="focus-visible:ring-ring rounded-sm font-semibold tracking-tight focus-visible:ring-2 focus-visible:outline-none"
        >
          upkeep
        </Link>
        <span aria-hidden="true" className="text-topbar-muted">
          /
        </span>
        <span data-slot="workspace" title={data.workspaceName} className="max-w-48 truncate">
          {data.workspaceName}
        </span>
      </div>

      {/* Below md: full-bleed second row (grow cancels the negative margins). */}
      <TopBarTabs className="order-last -mx-4 h-10 grow basis-full px-1 sm:-mx-6 sm:px-3 md:order-none md:mx-0 md:h-12 md:grow-0 md:basis-auto md:px-0" />

      <div className="ml-auto flex h-12 items-center gap-2">
        <Search />
        {data.firingAlerts > 0 && <FiringAlerts count={data.firingAlerts} />}
        <UserMenu user={user} />
      </div>
    </header>
  );
}

function FiringAlerts({ count }: { count: number }) {
  return (
    <Link
      href="/dashboard/alerts?state=firing"
      aria-label={`${count} firing ${count === 1 ? "alert" : "alerts"}`}
      className="hover:bg-topbar-foreground/10 focus-visible:ring-ring inline-flex h-8 items-center gap-2 rounded-md px-2 text-sm font-medium tabular-nums focus-visible:ring-2 focus-visible:outline-none"
    >
      <span aria-hidden="true" className="relative flex size-2">
        <span className="bg-sev-critical absolute inline-flex size-full rounded-full opacity-75 motion-safe:animate-ping" />
        <span className="bg-sev-critical relative inline-flex size-2 rounded-full" />
      </span>
      {count}
    </Link>
  );
}
