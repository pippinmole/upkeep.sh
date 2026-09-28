/// <reference types="bun" />

import { describe, expect, test } from "bun:test";
import example from "@/lib/report-snapshot.example.json";
import type {
  ReportHostAction,
  ReportHostRef,
  ReportImageAction,
  ReportSnapshot,
} from "@/lib/report-snapshot";
import { renderReportEmail } from "./render-report";
import { CONVENIENT_CAP, SECTION_CAP } from "./report-content";

const fixture = example as ReportSnapshot;
const url = "https://upkeep.example.com/dashboard/reports/d4e5f6a7-b8c9-4d0e-8f1a-2b3c4d5e6f7a";

const HEADINGS = [
  "Headline numbers",
  "Patch now",
  "Patch this week",
  "Images to update",
  "When convenient",
  "Reboots required",
  "No fix available yet",
  "Coverage gaps",
  "Estate",
];

function hosts(n: number): ReportHostRef[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    name: `host-${i}`,
  }));
}

// A big estate: every list far past its cap, every item with long name lists.
function largeSnapshot(): ReportSnapshot {
  const many = hosts(400);
  const base = fixture.host_actions[0];
  const hostActions: ReportHostAction[] = Array.from({ length: 600 }, (_, i) => ({
    ...base,
    tier: i < 200 ? "patch_now" : i < 400 ? "patch_this_week" : "when_convenient",
    package: `package-with-a-longish-name-${i}`,
    binary_packages: Array.from({ length: 12 }, (_, j) => `lib-binary-${i}-${j}`),
    cves: Array.from({ length: 40 }, (_, j) => `CVE-2026-${10000 + i * 40 + j}`),
    cve_count: 40,
    hosts: many,
    host_count: many.length,
  }));
  const img = fixture.image_actions[0];
  const imageActions: ReportImageAction[] = Array.from({ length: 300 }, (_, i) => ({
    ...img,
    image_refs: [`registry.example.com/team/service-${i}:2026.09.${i}`, `service-${i}:latest`],
    containers: Array.from({ length: 50 }, (_, j) => `container-${i}-${j}`),
    hosts: many,
  }));
  return {
    ...fixture,
    host_actions: hostActions,
    image_actions: imageActions,
    reboots_required: many.map((h) => ({
      host_id: h.id,
      host_name: h.name,
      packages: ["linux-image-5.15.0-122-generic", "libc6", "systemd"],
      since: "2026-09-25T03:14:00Z",
    })),
    coverage: {
      stale_agents: many.map((h, i) => ({
        agent_id: h.id,
        name: `agent-${i}`,
        last_seen_at: null,
        hosts: [h],
      })),
      hosts_without_docker: many,
      images_not_scored: [],
    },
    changes: {
      ...fixture.changes!,
      hosts_added: many.map((h) => ({
        ...h,
        contribution: { patch_now: 200, patch_this_week: 200, total_open_findings: 9000 },
      })),
    },
  };
}

function emptyCoverage(): ReportSnapshot {
  return {
    ...fixture,
    headline: { ...fixture.headline, stale_agents: 0 },
    coverage: { stale_agents: [], hosts_without_docker: [], images_not_scored: [] },
  };
}

describe("report email", () => {
  test("renders the shared fixture", async () => {
    const r = await renderReportEmail(fixture, url);
    expect(r.subject).toBe(
      "[upkeep.sh] Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting",
    );
    for (const h of HEADINGS) {
      expect(r.html).toContain(h);
      expect(r.text).toContain(h);
    }
    for (const v of [
      "openssl → 3.0.2-0ubuntu1.18",
      "curl → 7.81.0-1ubuntu1.21",
      "nginx:1.27",
      "CVE-2026-1001",
      "backup-agent",
      "linux-image-5.15.0-122-generic",
      "EPSS 94.3%",
      "KEV",
      "Ubuntu Pro",
    ]) {
      expect(r.html).toContain(v);
      expect(r.text).toContain(v);
    }
    // Week-on-week: absolute always, percent only when given.
    expect(r.text).toMatch(/Open findings\s+42 {2}\+12 \(\+40%\)\n/);
    expect(r.text).toMatch(/Patch now\s+1 {2}\+1\n/);
    expect(r.text).toMatch(/Patch this week\s+2 {2}no change\n/);
    expect(r.text).toMatch(/Resolved since last report\s+3 {2}−3\n/);
    expect(r.html).toContain("+12 (+40%)");
    expect(r.text).toContain(
      "db-1 was added since the last report; it accounts for 1 of the 1 to patch now, 1 of the 2 to patch this week, 2 of the 14 findings with no fix, 9 of the 42 open findings.",
    );
    expect(r.html).toContain(`href="${url}"`);
    expect(r.html).not.toContain("…and");
  });

  test("no comparison without a previous report", async () => {
    const r = await renderReportEmail({ ...fixture, changes: null }, null);
    expect(r.text).not.toContain("since the last report");
    expect(r.text).toMatch(/Open findings\s+42\n/);
    expect(r.html).not.toContain("href=");
  });

  test("notes a ranking version change", async () => {
    const r = await renderReportEmail(
      { ...fixture, changes: { ...fixture.changes!, comparable: false, metrics: {} } },
      url,
    );
    expect(r.text).toContain("tier numbers aren't compared");
  });

  test("coverage gaps section is always there", async () => {
    const r = await renderReportEmail(emptyCoverage(), url);
    expect(r.html).toContain("Coverage gaps");
    expect(r.html).toContain("No coverage gaps");
    expect(r.text).toContain("No coverage gaps");
  });

  test("large estate: capped lists and under Gmail's clip limit", async () => {
    const r = await renderReportEmail(largeSnapshot(), url);
    const bytes = new TextEncoder().encode(r.html).length;
    expect(bytes).toBeLessThan(100 * 1024);
    // 200 per host tier, capped; images 300; reboots and coverage 400.
    expect(r.html).toContain(`…and ${200 - SECTION_CAP} more, see the full report`);
    expect(r.html).toContain(`…and ${200 - CONVENIENT_CAP} more, see the full report`);
    expect(r.html).toContain(`…and ${300 - SECTION_CAP} more, see the full report`);
    expect(r.html).toContain(`…and ${800 - SECTION_CAP} more, see the full report`);
    expect(r.text).toContain(`…and ${400 - SECTION_CAP} more, see the full report: ${url}`);
    expect(r.text).toContain("host-0, host-1");
    expect(r.text).toContain("and 392 more");
  });

  test("more line is plain text without a report URL", async () => {
    const r = await renderReportEmail(largeSnapshot(), null);
    expect(r.text).toContain(`…and ${400 - SECTION_CAP} more, see the full report\n`);
    expect(r.html).not.toContain("href=");
  });
});
