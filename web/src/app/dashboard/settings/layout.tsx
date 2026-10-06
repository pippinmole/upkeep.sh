import { PageHeader } from "@/components/layout/page-header";

import { SettingsNav } from "./settings-nav";

// Settings: account-wide configuration, one route per section (listed in
// components/layout/settings-sections.ts): alert rules, notification
// channels, members and integrations. Report schedules are under Reports.
// A title band across the page, then the section links beside the content;
// both use the same padding so the title, links and content line up.
export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-0 min-w-0 flex-1 flex-col">
      <PageHeader
        title="Settings"
        description="Configure how upkeep.sh works for everyone on this install."
        className="border-b px-4 py-6 sm:px-6"
      />
      <div className="flex min-w-0 flex-1 flex-col gap-4 px-4 py-4 sm:px-6 sm:py-6 md:flex-row md:gap-8">
        <SettingsNav />
        <main className="flex min-w-0 flex-1 flex-col">{children}</main>
      </div>
    </div>
  );
}
