import { owned } from "../owner";
import type { AttentionProvider } from "../types";

// No enabled notification channel: alert rules still evaluate and show in
// the dashboard, but nobody is told. (The seeded default rule starts with
// no channel, by design: ALERTING.md "Default rules".)

export type ChannelData = { total: number; enabled: number };

const SQL = `
  SELECT count(*) AS total, count(*) FILTER (WHERE c.enabled) AS enabled
  FROM notification_channels c
  WHERE ${owned("c")}`;

export const channels: AttentionProvider<ChannelData> = {
  key: "channels",
  load: async (ctx) => {
    const [r] = await ctx.query<{ total: string; enabled: string }>(SQL);
    return { total: Number(r?.total ?? 0), enabled: Number(r?.enabled ?? 0) };
  },
  map: ({ total, enabled }) =>
    enabled > 0
      ? []
      : [
          {
            key: "channels",
            severity: "low",
            tone: "info",
            icon: "channel",
            title:
              total === 0
                ? "No notification channel set up"
                : "Every notification channel is disabled",
            why:
              total === 0
                ? "Alerts only show here: add email, a webhook or ntfy to be told when one fires."
                : "Alerts only show here: enable a channel to be told when one fires.",
            count: null,
            href: "/dashboard/settings/channels",
          },
        ],
};
