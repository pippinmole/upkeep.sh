import { PageHeader } from "@/components/layout/page-header";
import { NotificationSettingsLink } from "@/components/notifications/links";

import { AlertTabs } from "./alert-tabs";

// Alerts: what is worth telling you about (rules) and what was sent
// (delivery log). Each tab is its own route. Where alerts go (channels)
// lives under Settings -> Channels.
export default function AlertsLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col gap-4 p-4 sm:p-6">
      <PageHeader
        title="Alerts"
        description={
          <>
            Alert rules decide what is worth telling you about; the delivery log shows what was
            sent. Where alerts go is set up in <NotificationSettingsLink />.
          </>
        }
      />
      <AlertTabs />
      <div className="mt-2">{children}</div>
    </main>
  );
}
