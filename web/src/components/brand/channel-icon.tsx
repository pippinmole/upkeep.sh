import { Bell, type LucideIcon, Mail, Webhook } from "lucide-react";

import { MarkOrIcon } from "./brand-mark";
import type { BrandMarkName } from "./marks";

// Notification channel type (lib/notifier-types.json) → icon. Types with a
// brand get its mark; the rest a lucide icon; unknown types a bell.
const CHANNEL_MARKS: Record<string, BrandMarkName> = {
  ntfy: "ntfy",
  slack: "slack",
  discord: "discord",
  telegram: "telegram",
};

const CHANNEL_ICONS: Record<string, LucideIcon> = {
  email: Mail,
  webhook: Webhook,
};

// Decorative by default (it sits next to the channel name or type label);
// pass `title` to give it an accessible name.
export function ChannelIcon({
  type,
  size = 16,
  className,
  title = "",
}: {
  type: string;
  size?: number;
  className?: string;
  title?: string;
}) {
  return (
    <MarkOrIcon
      mark={CHANNEL_MARKS[type]}
      fallback={CHANNEL_ICONS[type] ?? Bell}
      size={size}
      className={className}
      title={title}
    />
  );
}
