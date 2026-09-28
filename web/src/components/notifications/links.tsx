import Link from "next/link";
import type { ReactNode } from "react";

// Channels live under Settings, rules under Alerts; these cross-links let
// people find one from the other. No "use client": usable from server and
// client components alike.
export const NOTIFICATION_SETTINGS_URL = "/dashboard/settings/notifications";
export const ALERTS_URL = "/dashboard/alerts";

// A stored report: the link target of report emails and ntfy (the worker
// builds SW_DASHBOARD_URL + this path), so the shape is fixed.
export function reportHref(reportId: string): string {
  return `/dashboard/reports/${reportId}`;
}

// One schedule's past reports, under Settings like the schedule itself.
export function scheduleReportsHref(scheduleId: string): string {
  return `${NOTIFICATION_SETTINGS_URL}/reports/${scheduleId}`;
}

// The delivery log narrowed to one notification's deliveries.
export function deliveryLogHref(notificationId: string): string {
  return `${ALERTS_URL}/log?notification=${notificationId}`;
}

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
