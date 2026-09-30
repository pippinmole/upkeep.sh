import type { EstateHealth, HostHealth } from "@/lib/queries-overview";

import { hostHref, nameList } from "../rank";
import type { AttentionItem, AttentionProvider } from "../types";

// Items read from the Overview's estate health (lib/queries-overview.ts),
// which the Estate card loads anyway: no query of their own. The firing
// alert count is the alerting feature's (the same count as the sidebar's
// Alerts badge).

function hostList(hosts: HostHealth[], many: string) {
  return {
    count: hosts.length,
    subject: nameList(hosts.map((h) => h.name)),
    href: hostHref(hosts.length, hosts[0]?.id ?? null, many),
  };
}

function fromEstate(
  key: string,
  map: (estate: EstateHealth) => AttentionItem[],
): AttentionProvider<EstateHealth> {
  return { key, load: async (ctx) => ctx.estate, map };
}

export const criticalImages = fromEstate("images", ({ signals }) =>
  signals.criticalImages > 0
    ? [
        {
          key: "images",
          severity: "high",
          tone: "danger",
          icon: "image",
          title: "Images in use with critical vulnerabilities",
          why: "Rebuild or re-pull these images: a host upgrade doesn't fix them.",
          count: signals.criticalImages,
          href: "/dashboard/images",
        },
      ]
    : [],
);

export const firingAlerts = fromEstate("alerts", ({ signals }) =>
  signals.firingAlerts > 0
    ? [
        {
          key: "alerts",
          severity: "high",
          tone: "warning",
          icon: "alert",
          title: signals.firingAlerts === 1 ? "Alert firing" : "Alerts firing",
          why: "A condition your alert rules watch for is true right now.",
          count: signals.firingAlerts,
          href: "/dashboard/alerts",
        },
      ]
    : [],
);

export const staleHosts = fromEstate("stale", ({ hosts }) => {
  const stale = hosts.filter((h) => h.stale && h.reported);
  if (stale.length === 0) return [];
  return [
    {
      key: "stale",
      severity: "high",
      tone: "warning",
      icon: "stale",
      title: stale.length === 1 ? "Host not reporting" : "Hosts not reporting",
      why: "Their agent went quiet: everything shown for them is getting older.",
      ...hostList(stale, "/dashboard/agents"),
    },
  ];
});

export const rebootRequired = fromEstate("reboot", ({ hosts }) => {
  const reboot = hosts.filter((h) => h.reboot);
  if (reboot.length === 0) return [];
  return [
    {
      key: "reboot",
      severity: "medium",
      tone: "warning",
      icon: "reboot",
      title: "Reboot required",
      why: "Installed updates (often the kernel) only take effect after a reboot.",
      ...hostList(reboot, "/dashboard/hosts"),
    },
  ];
});

export const failedDeliveries = fromEstate("deliveries", ({ signals }) =>
  signals.failedDeliveries > 0
    ? [
        {
          key: "deliveries",
          severity: "medium",
          tone: "warning",
          icon: "delivery",
          title: "Failed notification deliveries in the last 7 days",
          why: "Alerts didn't reach you: check the channel's settings in the delivery log.",
          count: signals.failedDeliveries,
          href: "/dashboard/alerts/log",
        },
      ]
    : [],
);

export const neverConnected = fromEstate("never", ({ signals }) => {
  const names = signals.neverConnected;
  if (names.length === 0) return [];
  return [
    {
      key: "never",
      severity: "low",
      tone: "info",
      icon: "agent",
      title: names.length === 1 ? "Agent never connected" : "Agents never connected",
      subject: nameList(names),
      why: "Registered but never pushed: finish the install, or revoke the agent.",
      count: names.length,
      href: "/dashboard/agents",
    },
  ];
});

export const waitingHosts = fromEstate("waiting", ({ hosts }) => {
  const waiting = hosts.filter((h) => !h.reported);
  if (waiting.length === 0) return [];
  return [
    {
      key: "waiting",
      severity: "low",
      tone: "neutral",
      icon: "waiting",
      title: "Waiting for a first report",
      why: "Added but no snapshot yet: check the agent can reach the server.",
      ...hostList(waiting, "/dashboard/hosts"),
    },
  ];
});
