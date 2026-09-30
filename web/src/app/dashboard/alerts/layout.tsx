import { PageHeader } from "@/components/layout/page-header";
import { AlertRulesLink, NotificationSettingsLink } from "@/components/notifications/links";

import { AlertTabs } from "./alert-tabs";

// Alerts: what the alert rules found (firing and resolved) and what was
// sent (delivery log). Each tab is its own route. The rules themselves and
// where alerts go (channels) live under Settings.
export default function AlertsLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <PageHeader
        title="Alerts"
        description={
          <>
            Alerts your <AlertRulesLink /> raised, and the delivery log of what was sent. Where
            alerts go is set up in <NotificationSettingsLink />.
          </>
        }
      />
      <AlertTabs />
      <div className="mt-2">{children}</div>
    </main>
  );
}
