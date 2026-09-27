import { Bell } from "lucide-react";

import { NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";

import type { NavGroup } from "./types";

export const SETTINGS_URL = "/dashboard/settings";

// Settings sections, shared by the sidebar's Settings button, the settings
// sub-nav and the command menu. Add an entry (and a route under
// app/dashboard/settings/) for each new section.
export const settingsSections = [
  { title: "Notification settings", url: NOTIFICATION_SETTINGS_URL, icon: Bell },
];

export const settingsNavGroup: NavGroup = { title: "Settings", items: settingsSections };
