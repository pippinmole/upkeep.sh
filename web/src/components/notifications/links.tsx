import Link from "next/link";
import type { ReactNode } from "react";

// Channels and alert rules live under Settings, firing alerts under
// Alerts, schedules under Reports; these cross-links let people find one
// from another. No "use
// client": usable from server and client components alike.
export const CHANNELS_URL = "/dashboard/settings/channels";
// The old name, from when the page was "Notification settings".
export const NOTIFICATION_SETTINGS_URL = CHANNELS_URL;
export const ALERTS_URL = "/dashboard/alerts";
export const ALERT_RULES_URL = "/dashboard/settings/alert-rules";
export const REPORTS_URL = "/dashboard/reports";

// A stored report: the link target of report emails and ntfy (the worker
// builds SW_DASHBOARD_URL + this path), so the shape is fixed.
export function reportHref(reportId: string): string {
  return `${REPORTS_URL}/${reportId}`;
}

// One schedule's past reports.
export function scheduleReportsHref(scheduleId: string): string {
  return `${REPORTS_URL}/schedules/${scheduleId}`;
}

// The delivery log narrowed to one notification's deliveries.
export function deliveryLogHref(notificationId: string): string {
  return `${ALERTS_URL}/log?notification=${notificationId}`;
}

export function NotificationSettingsLink({ children }: { children?: ReactNode }) {
  return (
    <Link href={CHANNELS_URL} className="text-foreground font-medium underline underline-offset-4">
      {children ?? "Settings → Channels"}
    </Link>
  );
}

export function AlertRulesLink() {
  return (
    <Link
      href={ALERT_RULES_URL}
      className="text-foreground font-medium underline underline-offset-4"
    >
      alert rules
    </Link>
  );
}
