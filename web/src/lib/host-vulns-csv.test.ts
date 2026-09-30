/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { HOST_VULNS_CSV_HEADER, hostVulnsCsv, hostVulnsCsvFilename } from "./host-vulns-csv";
import { hasHostVulnFilters, parseHostVulnFilters, searchParamsOf } from "./host-vulns-filters";
import type { ExportFindingRow } from "./queries-host-vulns-export";

const base: ExportFindingRow = {
  vulnKey: "CVE-2026-35189",
  aliases: ["GHSA-aaaa-bbbb-cccc"],
  advisoryIds: ["UBUNTU-CVE-2026-35189", "USN-8847-1"],
  status: "open",
  severity: "high",
  distroSeverity: "medium",
  cvssV3Score: 7.5,
  cvssV3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
  epssScore: 0.01234,
  epssPercentile: 0.5,
  isKev: true,
  kevAddedAt: "2026-01-02",
  kevDueDate: "2026-01-23",
  sourcePackage: "openssl",
  packages: ["libssl3", "openssl"],
  installedVersion: "3.0.13-0ubuntu3.4",
  fixedVersion: "3.0.13-0ubuntu3.5",
  fixChannel: "standard",
  requiresPro: false,
  fixAdvisoryId: "USN-8847-1",
  kernelRelease: null,
  runningKernelUnknown: false,
  publishedAt: "2026-01-01T00:00:00.000Z",
  firstSeenAt: "2026-02-03T04:05:06.000Z",
  reopenedAt: null,
  reopenCount: 0,
  resolvedAt: null,
  description: 'A "crafted" packet, sent twice,\ncrashes the server.',
};

// Minimal RFC 4180 parser for round-trip checks.
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (ch === '"') quoted = false;
      else field += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\r" && text[i + 1] === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      i++;
    } else field += ch;
  }
  return rows;
}

describe("hostVulnsCsv", () => {
  test("header row, then one record per finding", () => {
    const rows = parseCsv(hostVulnsCsv([base, { ...base, vulnKey: "CVE-2026-1" }]));
    expect(rows).toHaveLength(3);
    expect(rows[0]).toEqual([...HOST_VULNS_CSV_HEADER]);
    for (const r of rows) expect(r).toHaveLength(HOST_VULNS_CSV_HEADER.length);
  });

  test("maps a finding to its columns", () => {
    const [, rec] = parseCsv(hostVulnsCsv([base]));
    const byHeader = Object.fromEntries(HOST_VULNS_CSV_HEADER.map((h, i) => [h, rec[i]]));
    expect(byHeader).toMatchObject({
      "Vulnerability ID": "CVE-2026-35189",
      Aliases: "GHSA-aaaa-bbbb-cccc",
      Advisories: "UBUNTU-CVE-2026-35189; USN-8847-1",
      Severity: "high",
      "CVSS v3 score": "7.5",
      "Known exploited (KEV)": "yes",
      "Binary packages": "libssl3; openssl",
      "Fix status": "available",
      "Reopen count": "0",
      Resolved: "",
      Description: 'A "crafted" packet, sent twice,\ncrashes the server.',
    });
  });

  test("fix status covers pro-only and unfixed findings", () => {
    const csv = parseCsv(
      hostVulnsCsv([
        { ...base, fixChannel: "ubuntu-pro", requiresPro: true },
        { ...base, fixedVersion: null, fixChannel: null },
      ]),
    );
    const col = HOST_VULNS_CSV_HEADER.indexOf("Fix status");
    expect(csv[1][col]).toBe("ubuntu-pro");
    expect(csv[2][col]).toBe("none");
  });

  test("neutralises formula injection in feed and agent data", () => {
    const out = hostVulnsCsv([
      { ...base, sourcePackage: "=cmd|' /C calc'!A0", installedVersion: "+1", description: "@x" },
    ]);
    const [, rec] = parseCsv(out);
    const col = (h: string) => rec[HOST_VULNS_CSV_HEADER.indexOf(h)];
    expect(col("Source package")).toBe("'=cmd|' /C calc'!A0");
    expect(col("Installed version")).toBe("'+1");
    expect(col("Description")).toBe("'@x");
  });

  test("no findings is just the header", () => {
    expect(parseCsv(hostVulnsCsv([]))).toEqual([[...HOST_VULNS_CSV_HEADER]]);
  });
});

describe("hostVulnsCsvFilename", () => {
  const day = new Date("2026-09-30T23:59:00Z");
  test("hostname and UTC date", () => {
    expect(hostVulnsCsvFilename("db196502fa70", day)).toBe(
      "db196502fa70-vulnerabilities-2026-09-30.csv",
    );
  });
  test("unsafe characters are replaced", () => {
    expect(hostVulnsCsvFilename('../we"ird host\r\n', day)).toBe(
      "we_ird_host_-vulnerabilities-2026-09-30.csv",
    );
    expect(hostVulnsCsvFilename("", day)).toBe("host-vulnerabilities-2026-09-30.csv");
  });
});

describe("parseHostVulnFilters", () => {
  test("defaults to every open finding", () => {
    const f = parseHostVulnFilters({});
    expect(f).toEqual({
      status: "open",
      q: null,
      severity: null,
      kev: false,
      fix: null,
      sort: "severity",
    });
    expect(hasHostVulnFilters(f)).toBe(false);
  });

  test("reads the page's params and ignores page/v and bad values", () => {
    const sp = searchParamsOf(
      new URLSearchParams(
        "status=resolved&q=ssl&severity=high&kev=1&fix=pro&sort=recent&page=3&v=CVE-1",
      ),
    );
    const f = parseHostVulnFilters(sp);
    expect(f).toEqual({
      status: "resolved",
      q: "ssl",
      severity: "high",
      kev: true,
      fix: "pro",
      sort: "recent",
    });
    expect(hasHostVulnFilters(f)).toBe(true);
    expect(parseHostVulnFilters({ severity: "bogus", fix: "all" }).severity).toBeNull();
  });
});
