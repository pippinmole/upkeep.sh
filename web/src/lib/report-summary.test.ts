/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import example from "./report-snapshot.example.json";
import type { ReportSnapshot } from "./report-snapshot";
import { reportEmailSubject, reportSummary, reportTitle } from "./report-summary";

const fixture = example as ReportSnapshot;

function withHeadline(
  headline: Partial<ReportSnapshot["headline"]>,
  staleHosts: string[][] = [],
): ReportSnapshot {
  return {
    ...fixture,
    headline: {
      ...fixture.headline,
      patch_now: 0,
      patch_this_week: 0,
      images_to_update: 0,
      stale_agents: 0,
      ...headline,
    },
    coverage: {
      ...fixture.coverage,
      stale_agents: staleHosts.map((ids, i) => ({
        agent_id: `agent-${i}`,
        name: `agent-${i}`,
        last_seen_at: null,
        hosts: ids.map((id) => ({ id, name: id })),
      })),
    },
  };
}

describe("report summary", () => {
  // The Go side (ntfy title) must produce exactly this for the same fixture.
  test("shared fixture", () => {
    expect(reportSummary(fixture)).toBe(
      "1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting",
    );
    expect(reportTitle(fixture)).toBe(
      "Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting",
    );
    expect(reportEmailSubject(fixture)).toBe(
      "[upkeep.sh] Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting",
    );
  });

  test("all clear", () => {
    expect(reportSummary(withHeadline({}))).toBe("all clear");
  });

  test("plurals and order", () => {
    const s = withHeadline(
      { patch_now: 2, patch_this_week: 1, images_to_update: 3, stale_agents: 1 },
      [["h1", "h2"]],
    );
    expect(reportSummary(s)).toBe(
      "2 urgent actions, 1 to patch this week, 3 images to update, 2 hosts not reporting",
    );
  });

  test("hosts counted once across agents", () => {
    const s = withHeadline({ stale_agents: 2 }, [["h1", "h2"], ["h2"]]);
    expect(reportSummary(s)).toBe("2 hosts not reporting");
  });

  test("stale agents with no hosts fall back to agents", () => {
    expect(reportSummary(withHeadline({ stale_agents: 1 }, [[]]))).toBe("1 agent not reporting");
    expect(reportSummary(withHeadline({ stale_agents: 3 }))).toBe("3 agents not reporting");
  });

  test("skips zero parts", () => {
    expect(reportSummary(withHeadline({ images_to_update: 1 }))).toBe("1 image to update");
  });
});
