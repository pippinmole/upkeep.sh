/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import type { AttentionItem } from "@/lib/attention";
import type { EstateHealth } from "@/lib/queries-overview";

import { BASE, resultText, testCtx, testDeps, WORKSPACE } from "../test-utils";
import { attentionTool } from "./attention";

const estate: EstateHealth = {
  hosts: [],
  signals: {} as EstateHealth["signals"],
};

function item(key: string, over: Partial<AttentionItem> = {}): AttentionItem {
  return {
    key,
    severity: "high",
    tone: "danger",
    icon: "vuln",
    title: `${key} title`,
    why: `${key} why`,
    count: 1,
    href: `/dashboard/${key}`,
    ...over,
  };
}

function tool(items: AttentionItem[]) {
  return attentionTool({
    getEstateHealth: async (ws) => {
      expect(ws).toBe(WORKSPACE);
      return estate;
    },
    getAttentionItems: async (ws, e) => {
      expect(ws).toBe(WORKSPACE);
      expect(e).toBe(estate); // the same estate, as on the Overview
      return items;
    },
  });
}

describe("list_attention_items", () => {
  test("the Overview's items in its order, with links", async () => {
    const { deps, logged } = testDeps();
    const res = await tool([
      item("kev", { severity: "critical", subject: "web-01, web-02" }),
      item("stale", { severity: "medium", count: null }),
    ]).call({}, testCtx, deps);
    expect(res.structuredContent).toEqual({
      items: [
        {
          key: "kev",
          severity: "critical",
          title: "kev title",
          subject: "web-01, web-02",
          why: "kev why",
          count: 1,
          dashboard_url: `${BASE}/dashboard/kev`,
        },
        {
          key: "stale",
          severity: "medium",
          title: "stale title",
          subject: null,
          why: "stale why",
          count: null,
          dashboard_url: `${BASE}/dashboard/stale`,
        },
      ],
      total: 2,
      truncated: false,
      dashboard_url: `${BASE}/dashboard`,
    });
    expect(logged[0]).toMatchObject({ arguments: { limit: 15 }, resultItems: 2 });
    expect(resultText(res)).toContain("- [critical] kev title (web-01, web-02): kev why");
  });

  test("limit and the truncated flag", async () => {
    const { deps } = testDeps();
    const items = Array.from({ length: 4 }, (_, i) => item(`k${i}`));
    const res = await tool(items).call({ limit: 3 }, testCtx, deps);
    expect(res.structuredContent).toMatchObject({ total: 4, truncated: true });
    expect((res.structuredContent as { items: unknown[] }).items).toHaveLength(3);
    const bad = await tool(items).call({ limit: 101 }, testCtx, deps);
    expect(bad.isError).toBe(true);
  });

  test("nothing to do", async () => {
    const { deps } = testDeps();
    const res = await tool([]).call({}, testCtx, deps);
    expect(resultText(res)).toStartWith("Nothing needs attention");
  });
});
