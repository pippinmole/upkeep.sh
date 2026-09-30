/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { GROUP_LIMIT, searchTerms } from "./query";
import { SEARCH_GROUPS, feedVulnQuery, groupQuery, groupsFor } from "./sql";

const WS = "00000000-0000-0000-0000-000000000001";
const terms = (q: string) => {
  const t = searchTerms(q);
  if (!t) throw new Error("too short");
  return t;
};

describe("groupQuery", () => {
  test("every group binds workspace, exact key, patterns and limit", () => {
    const t = terms("Nginx%");
    for (const g of SEARCH_GROUPS) {
      const { values } = groupQuery(g, WS, t);
      expect(values).toEqual([WS, "nginx%", "%Nginx\\%%", "Nginx\\%%", GROUP_LIMIT]);
    }
  });

  test("user text is never interpolated into the SQL", () => {
    const evil = "x'; DROP TABLE hosts; --";
    for (const g of SEARCH_GROUPS) {
      const { text, values } = groupQuery(g, WS, terms(evil));
      expect(text).not.toContain("DROP TABLE");
      expect(values).toContain(`%${evil}%`);
    }
  });

  test("every group is scoped to the workspace and limited", () => {
    for (const g of SEARCH_GROUPS) {
      const { text } = groupQuery(g, WS, terms("ab"));
      expect(text).toMatch(/\.workspace_id = \$1/);
      expect(text).toContain("LIMIT $5");
    }
  });

  test("groups other than hosts and agents skip archived hosts", () => {
    for (const g of ["vulnerabilities", "packages", "images", "containers"] as const) {
      expect(groupQuery(g, WS, terms("ab")).text).toContain("h.archived_at IS NULL");
    }
  });

  test("vulnerabilities read the workspace's findings, not the CVE feed", () => {
    const { text } = groupQuery("vulnerabilities", WS, terms("CVE-2024"));
    expect(text).toContain("JOIN findings f ON f.host_id = h.id");
    expect(text).not.toMatch(/\bcves\b/);
    expect(text).not.toMatch(/\badvisories\b/);
  });

  test("a custom limit", () => {
    expect(groupQuery("hosts", WS, terms("ab"), 20).values[4]).toBe(20);
  });
});

describe("groupsFor", () => {
  test("two characters skip the trigram-indexed groups", () => {
    expect(groupsFor(terms("db"))).toEqual(["images", "containers", "hosts", "agents"]);
  });

  test("three characters and up query every group", () => {
    expect(groupsFor(terms("ssl"))).toEqual(SEARCH_GROUPS);
  });
});

describe("feedVulnQuery", () => {
  test("only for an exact advisory id, bound in canonical form", () => {
    expect(feedVulnQuery(WS, terms("CVE-2024"))).toBeNull();
    expect(feedVulnQuery(WS, terms("openssl"))).toBeNull();
    const q = feedVulnQuery(WS, terms("cve-2024-3094"));
    expect(q?.values).toEqual(["CVE-2024-3094", WS]);
    // Point lookups only: no pattern match on the feed tables.
    expect(q?.text).not.toContain("ILIKE");
  });

  test("the workspace's findings for the id are scoped to the workspace", () => {
    expect(feedVulnQuery(WS, terms("USN-6700-1"))?.text).toContain("h.workspace_id = $2");
  });
});
