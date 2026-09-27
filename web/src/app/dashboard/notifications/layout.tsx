import { NotificationTabs } from "./notification-tabs";

// Notifications: where alerts go (channels), what triggers them (rules),
// and what was sent (delivery log). Each tab is its own route.
export default function NotificationsLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="flex min-h-0 flex-1 flex-col p-4 sm:p-6">
      <div>
        <h1 className="text-2xl font-bold">Notifications</h1>
        <p className="text-muted-foreground text-sm">
          Alert rules decide what is worth telling you about; channels decide where it goes.
        </p>
      </div>
      <div className="mt-4">
        <NotificationTabs />
      </div>
      <div className="mt-6">{children}</div>
    </main>
  );
}
