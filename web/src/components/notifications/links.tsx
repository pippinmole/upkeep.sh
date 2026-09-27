import Link from "next/link";
import type { ReactNode } from "react";

// Channels live under Settings, rules under Alerts; these cross-links let
// people find one from the other. No "use client": usable from server and
// client components alike.
export const NOTIFICATION_SETTINGS_URL = "/dashboard/settings/notifications";
export const ALERTS_URL = "/dashboard/alerts";

export function NotificationSettingsLink({ children }: { children?: ReactNode }) {
  return (
    <Link
      href={NOTIFICATION_SETTINGS_URL}
      className="text-foreground font-medium underline underline-offset-4"
    >
      {children ?? "Settings → Notification settings"}
    </Link>
  );
}
