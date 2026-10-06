import { PageHeader } from "@/components/layout/page-header";

import { SettingsNav } from "./settings-nav";

// Settings: account-wide configuration, one route per section (listed in
// components/layout/settings-sections.ts): alert rules, notification
// channels, members and integrations. Report schedules are under Reports.
export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        title="Settings"
        description="Configure how upkeep.sh works for everyone on this install."
      />
      <div className="flex min-w-0 flex-col gap-6 md:flex-row">
        <aside className="md:w-52 md:shrink-0">
          <SettingsNav />
        </aside>
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </main>
  );
}
