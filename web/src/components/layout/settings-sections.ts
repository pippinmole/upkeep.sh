import { Send, Users } from "lucide-react";

import { NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";

export const SETTINGS_URL = "/dashboard/settings";

// Settings sections, shared by the sidebar's Settings button, the settings
// sub-nav and the command menu. Add an entry (and a route under
// app/dashboard/settings/) for each new section.
export const settingsSections = [
  {
    title: "Channels",
    url: NOTIFICATION_SETTINGS_URL,
    icon: Send,
    keywords: ["notifications", "email", "slack", "discord", "ntfy", "webhook"],
  },
  {
    title: "Members",
    url: `${SETTINGS_URL}/members`,
    icon: Users,
    keywords: ["users", "team", "roles", "administrator", "invite", "accounts", "password"],
  },
];
