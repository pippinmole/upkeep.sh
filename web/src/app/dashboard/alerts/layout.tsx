import { AlertTabs } from "./alert-tabs";

// Alerts: what is worth telling you about (rules) and what was sent
// (delivery log). Each tab is its own route. Where alerts go (channels)
// lives under Settings -> Notification settings.
export default function AlertsLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Alerts</h1>
        <p className="text-muted-foreground text-sm">
          Alert rules decide what is worth telling you about; the delivery log shows what was sent.
        </p>
      </div>
      <div className="mt-4">
        <AlertTabs />
      </div>
      <div className="mt-6">{children}</div>
    </main>
  );
}
