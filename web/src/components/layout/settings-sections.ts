import { BellRing, Plug, Send, Users } from "lucide-react";

import { INTEGRATIONS_URL } from "@/app/dashboard/settings/integrations/links";
import { ALERT_RULES_URL, NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";

export const SETTINGS_URL = "/dashboard/settings";

// Settings sections, shared by the sidebar's Settings button, the settings
// sub-nav and the command menu. Add an entry (and a route under
// app/dashboard/settings/) for each new section.
export const settingsSections = [
  {
    title: "Alert rules",
    url: ALERT_RULES_URL,
    icon: BellRing,
    keywords: ["alerts", "rules", "ports", "ssh", "conditions"],
  },
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
  {
    title: "Integrations",
    url: INTEGRATIONS_URL,
    icon: Plug,
    keywords: ["mcp", "claude", "ai", "oauth", "tokens", "api"],
  },
];
