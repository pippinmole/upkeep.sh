import { SettingsNav } from "./settings-nav";

// Settings: account-wide configuration, one route per section (listed in
// components/layout/settings-sections.ts). Only notification channels live
// here for now.
export default function SettingsLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-muted-foreground text-sm">Configure how upkeep.sh works for you.</p>
      </div>
      <div className="mt-6 flex min-w-0 flex-col gap-6 md:flex-row">
        <aside className="md:w-52 md:shrink-0">
          <SettingsNav />
        </aside>
        <div className="min-w-0 flex-1">{children}</div>
      </div>
    </main>
  );
}
