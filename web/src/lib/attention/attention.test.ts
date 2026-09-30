/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { EstateHealth, HostHealth } from "@/lib/queries-overview";

import { owned, activeHost } from "./owner";
import { channels } from "./providers/channels";
import { collectors, type CollectorHost } from "./providers/collectors";
import { duplicates } from "./providers/duplicates";
import { endOfLife } from "./providers/eol";
import { rebootRequired, staleHosts, waitingHosts, firingAlerts } from "./providers/estate";
import { vulnerabilities } from "./providers/vulns";
import { capItems, hostHref, nameList, rankItems } from "./rank";
import { ATTENTION_PROVIDERS } from "./registry";
import type { AttentionContext, AttentionItem, AttentionSeverity } from "./types";

function item(key: string, severity: AttentionSeverity): AttentionItem {
  return { key, severity, tone: "info", icon: "vuln", title: key, why: "", count: 1, href: "/" };
}

function host(name: string, over: Partial<HostHealth> = {}): HostHealth {
  return {
    id: `id-${name}`,
    name,
    state: "ok",
    reported: true,
    stale: false,
    reboot: false,
    kev: 0,
    critical: 0,
    ...over,
  };
}

function estate(hosts: HostHealth[], signals: Partial<EstateHealth["signals"]> = {}): EstateHealth {
  return {
    hosts,
    signals: {
      containers: 0,
      images: 0,
      criticalImages: 0,
      failedDeliveries: 0,
      firingAlerts: 0,
      neverConnected: [],
      ...signals,
    },
  };
}

describe("rankItems", () => {
  test("orders by severity, keeping registry order within a tier", () => {
    const ranked = rankItems([
      item("low-a", "low"),
      item("high-a", "high"),
      item("critical", "critical"),
      item("medium", "medium"),
      item("high-b", "high"),
      item("low-b", "low"),
    ]);
    expect(ranked.map((i) => i.key)).toEqual([
      "critical",
      "high-a",
      "high-b",
      "medium",
      "low-a",
      "low-b",
    ]);
  });

  test("capItems keeps the top items and counts the rest", () => {
    const items = ["a", "b", "c", "d"].map((k) => item(k, "high"));
    expect(capItems(items, 3)).toEqual({ shown: items.slice(0, 3), hidden: 1 });
    expect(capItems(items, 6)).toEqual({ shown: items, hidden: 0 });
  });
});

describe("helpers", () => {
  test("nameList shortens long lists", () => {
    expect(nameList(["a"])).toBe("a");
    expect(nameList(["a", "b", "c", "d", "e"])).toBe("a, b, c and 2 more");
    // SQL returns only the first few names with the total.
    expect(nameList(["a", "b", "c"], 10)).toBe("a, b, c and 7 more");
  });

  test("hostHref links one host to its page, several to the list", () => {
    expect(hostHref(1, "h1", "/dashboard/hosts")).toBe("/dashboard/hosts/h1");
    expect(hostHref(2, "h1", "/dashboard/hosts")).toBe("/dashboard/hosts");
    expect(hostHref(1, null, "/dashboard/hosts")).toBe("/dashboard/hosts");
  });

  test("ownership is one column, bound to $1", () => {
    expect(owned("c")).toBe("c.workspace_id = $1");
    expect(activeHost()).toBe("h.workspace_id = $1 AND h.archived_at IS NULL");
  });
});

describe("providers", () => {
  test("vulnerabilities: KEV is critical, fixable critical is high, zero is nothing", () => {
    expect(
      vulnerabilities.map({
        kev: 0,
        kevHosts: 0,
        kevFixable: 0,
        criticalFixable: 0,
        criticalFixableHosts: 0,
      }),
    ).toEqual([]);
    const items = vulnerabilities.map({
      kev: 4,
      kevHosts: 2,
      kevFixable: 3,
      criticalFixable: 7,
      criticalFixableHosts: 1,
    });
    expect(items.map((i) => [i.key, i.severity, i.count])).toEqual([
      ["kev", "critical", 4],
      ["critical-fixable", "high", 7],
    ]);
    expect(items[0].title).toBe("Known-exploited vulnerabilities on 2 hosts");
    expect(items[0].subject).toBe("3 with a fix available");
    expect(items[1].subject).toBe("On 1 host");
    expect(items[1].href).toBe(
      "/dashboard/vulnerabilities?kind=package&severity=critical&fix=available",
    );
  });

  test("collectors: exposed sockets and failing collectors are separate items", () => {
    const hosts: CollectorHost[] = [
      { id: "a", name: "web-1", socketsExposed: true, failed: [] },
      { id: "b", name: "db-1", socketsExposed: false, failed: ["deb_packages", "tcp_listeners"] },
    ];
    const items = collectors.map(hosts);
    expect(items.map((i) => [i.key, i.severity, i.count, i.href])).toEqual([
      ["host-sockets", "critical", 1, "/dashboard/hosts/a"],
      ["collectors", "medium", 1, "/dashboard/hosts/b"],
    ]);
    expect(items[1].subject).toBe("db-1 (deb_packages, tcp_listeners)");
    expect(collectors.map([])).toEqual([]);
  });

  test("end of life: past is high, soon is low, several hosts link to the list", () => {
    const items = endOfLife.map({
      past: { n: 5, names: ["a (Ubuntu 20.04)", "b (Debian 11)", "c (Debian 11)"], firstId: "a" },
      soon: { n: 1, names: ["d (Alpine 3.21)"], firstId: "d" },
    });
    expect(items.map((i) => [i.key, i.severity, i.count, i.href])).toEqual([
      ["eol", "high", 5, "/dashboard/hosts"],
      ["eol-soon", "low", 1, "/dashboard/hosts/d"],
    ]);
    expect(items[0].subject).toBe("a (Ubuntu 20.04), b (Debian 11), c (Debian 11) and 2 more");
  });

  test("duplicates and channels", () => {
    expect(duplicates.map({ n: 0, names: [] })).toEqual([]);
    expect(duplicates.map({ n: 2, names: ["x", "y"] })[0]).toMatchObject({
      key: "duplicates",
      count: 2,
      subject: "x, y",
      href: "/dashboard/hosts",
    });
    expect(channels.map({ total: 2, enabled: 1 })).toEqual([]);
    expect(channels.map({ total: 0, enabled: 0 })[0]).toMatchObject({
      title: "No notification channel set up",
      count: null,
    });
    expect(channels.map({ total: 1, enabled: 0 })[0].title).toBe(
      "Every notification channel is disabled",
    );
  });

  test("estate: stale excludes never-reported hosts, which are 'waiting'", () => {
    const e = estate(
      [
        host("a", { stale: true }),
        host("b", { stale: true, reported: false }),
        host("c", { reboot: true }),
      ],
      { firingAlerts: 1 },
    );
    expect(staleHosts.map(e)[0]).toMatchObject({
      count: 1,
      subject: "a",
      href: "/dashboard/hosts/id-a",
    });
    expect(waitingHosts.map(e)[0]).toMatchObject({ count: 1, subject: "b" });
    expect(rebootRequired.map(e)[0]).toMatchObject({ count: 1, severity: "medium" });
    expect(firingAlerts.map(e)[0]).toMatchObject({ title: "Alert firing", count: 1 });
    expect(rebootRequired.map(estate([]))).toEqual([]);
  });
});

describe("registry", () => {
  test("keys are unique", () => {
    const keys = ATTENTION_PROVIDERS.map((p) => p.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  test("runs every provider against a context and ranks nothing into nothing", async () => {
    const ctx: AttentionContext = {
      query: async () => [],
      estate: estate([]),
    };
    const lists = await Promise.all(ATTENTION_PROVIDERS.map((p) => p.run(ctx)));
    // With no rows and no channel, only "no channel" remains.
    expect(rankItems(lists.flat()).map((i) => i.key)).toEqual(["channels"]);
  });
});
