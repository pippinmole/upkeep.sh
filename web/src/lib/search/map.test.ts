/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import {
  mapAgent,
  mapContainer,
  mapFeedVuln,
  mapHost,
  mapImage,
  mapPackage,
  mapVuln,
  mergeVulns,
  type SearchResult,
} from "./map";

describe("row mapping", () => {
  test("host: label first, archived badge, host page", () => {
    expect(
      mapHost({ id: "h1", hostname: "ip-10-0-0-1", label: "web", os_id: "ubuntu", archived: true }),
    ).toEqual({
      id: "h1",
      title: "web (ip-10-0-0-1)",
      subtitle: "ubuntu",
      badge: "archived",
      href: "/dashboard/hosts/h1",
    });
    expect(
      mapHost({ id: "h2", hostname: "db", label: null, os_id: null, archived: false }).title,
    ).toBe("db");
  });

  test("agent: filtered Agents table, counts from Postgres bigint strings", () => {
    expect(
      mapAgent({
        id: "a1",
        name: "edge agent",
        platform: "linux/amd64",
        revoked: false,
        hosts: "1",
      }),
    ).toEqual({
      id: "a1",
      title: "edge agent",
      subtitle: "1 host · linux/amd64",
      badge: undefined,
      href: "/dashboard/agents?q=edge%20agent",
    });
    expect(mapAgent({ id: "a", name: "x", platform: null, revoked: true, hosts: 3 }).badge).toBe(
      "revoked",
    );
  });

  test("package: package page by name", () => {
    expect(mapPackage({ name: "libssl3", ecosystems: ["deb"], hosts: "2", versions: "1" })).toEqual(
      {
        id: "libssl3",
        title: "libssl3",
        subtitle: "deb · 2 hosts · 1 version",
        href: "/dashboard/packages/libssl3",
      },
    );
    expect(mapPackage({ name: "a+b", ecosystems: [], hosts: 1, versions: 1 }).href).toBe(
      "/dashboard/packages/a%2Bb",
    );
  });

  test("image: repository page, one segment per path component", () => {
    expect(mapImage({ repo: "ghcr.io/me/api", hosts: "2", tags: ["1.0", "latest"] })).toEqual({
      id: "ghcr.io/me/api",
      title: "ghcr.io/me/api",
      subtitle: "2 hosts · tags 1.0, latest",
      href: "/dashboard/images/ghcr.io/me/api",
    });
    expect(mapImage({ repo: "nginx", hosts: 1, tags: null }).subtitle).toBe("1 host");
  });

  test("container: host's Containers tab, state badge unless running", () => {
    const r = mapContainer({
      host_id: "h1",
      hostname: "web",
      label: null,
      container_id: "c".repeat(64),
      name: "/api-1",
      image: "ghcr.io/me/api:1.0",
      state: "exited",
    });
    expect(r).toEqual({
      id: `h1/${"c".repeat(64)}`,
      title: "api-1",
      subtitle: "on web · ghcr.io/me/api:1.0",
      badge: "exited",
      href: "/dashboard/hosts/h1/containers",
    });
  });

  test("vulnerability: detail page and open-host count", () => {
    expect(
      mapVuln({ vuln_key: "CVE-2024-3094", severity: "critical", is_kev: true, open_hosts: "2" }),
    ).toEqual({
      id: "CVE-2024-3094",
      title: "CVE-2024-3094",
      subtitle: "open on 2 hosts · critical",
      badge: "KEV",
      href: "/dashboard/vulnerabilities/CVE-2024-3094",
    });
    expect(
      mapVuln({ vuln_key: "DSA-1-1", severity: null, is_kev: false, open_hosts: 0 }).subtitle,
    ).toBe("resolved");
  });

  const feed = {
    vuln_key: "CVE-2021-44228",
    via_advisory: null,
    is_kev: true,
    cvss_v3_score: 10,
    description: "Log4Shell",
    severity: null,
    open_hosts: 0,
    findings: 0,
  };

  test("feed vulnerability not on the workspace's hosts says so, with CVSS", () => {
    expect(mapFeedVuln(feed).subtitle).toBe("not found on your hosts · CVSS 10.0 · Log4Shell");
  });

  test("feed vulnerability reached by alias, on the workspace's hosts", () => {
    expect(
      mapFeedVuln({
        ...feed,
        vuln_key: "CVE-2024-3094",
        via_advisory: "USN-6700-1",
        severity: "critical",
        open_hosts: "1",
        findings: "1",
      }).subtitle,
    ).toBe("via USN-6700-1 · open on 1 host · critical");
  });
});

describe("mergeVulns", () => {
  const r = (id: string): SearchResult => ({ id, title: id, href: `/v/${id}` });

  test("the exact id's feed entry goes first, within the limit", () => {
    const out = mergeVulns([r("a"), r("b"), r("c")], [r("x")], 3);
    expect(out.map((x) => x.id)).toEqual(["x", "a", "b"]);
  });

  test("an id in both isn't listed twice; the feed entry wins", () => {
    const x = { ...r("x"), subtitle: "via USN-1-1" };
    const out = mergeVulns([r("x"), r("a")], [x], 5);
    expect(out).toEqual([x, r("a")]);
  });
});
