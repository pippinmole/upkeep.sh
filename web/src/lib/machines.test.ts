/// <reference types="bun" />

import { expect, test } from "bun:test";
import {
  type AgentStatus,
  collectorLabel,
  filterMachines,
  hasNoActiveAgent,
  imageVulnsTitle,
  type MachineAgent,
  type MachineFilters,
  type MachineRow,
  machineStatus,
  machinesSummaryText,
  parseMachineFilters,
  summarizeMachines,
} from "./machines";

const a = (
  status: AgentStatus,
  mode: MachineAgent["mode"] = "local",
  name = "a1",
): MachineAgent => ({
  id: name,
  name,
  mode,
  status,
});

test("status: any online wins", () =>
  expect(machineStatus([a("stale"), a("online", "ssh")])).toBe("online"));
test("status: active but none online is stale", () =>
  expect(machineStatus([a("never"), a("stale")])).toBe("stale"));
test("status: all revoked is stale with no active agent", () => {
  expect(machineStatus([a("revoked")])).toBe("stale");
  expect(hasNoActiveAgent([a("revoked")])).toBe(true);
});
test("status: only never-reported agents is never", () =>
  expect(machineStatus([a("never")])).toBe("never"));
test("status: no agents is never, label null", () => {
  expect(machineStatus([])).toBe("never");
  expect(collectorLabel([])).toBeNull();
  expect(hasNoActiveAgent([])).toBe(false);
});
test("label: local agent first, more counted", () => {
  expect(collectorLabel([a("online", "local", "x"), a("online", "ssh", "bastion")])).toEqual({
    text: "Local agent",
    more: 1,
  });
});
test("label: remote names the agent", () => {
  expect(collectorLabel([a("online", "ssh", "bastion")])).toEqual({ text: "via bastion", more: 0 });
});
test("label: skips revoked when an active one exists", () => {
  expect(collectorLabel([a("revoked", "local", "old"), a("online", "ssh", "bastion")])).toEqual({
    text: "via bastion",
    more: 0,
  });
});
test("label: all revoked falls back to the first agent", () => {
  expect(collectorLabel([a("revoked", "ssh", "gone")])).toEqual({ text: "via gone", more: 0 });
});

const zero = { critical: 0, high: 0, medium: 0, low: 0, kev: 0 };
const noImg = { vulns: 0, critical: 0, kev: 0, images: 0 };
const m = (o: Partial<MachineRow> = {}): MachineRow => ({
  id: o.hostname ?? "m",
  hostname: "host",
  label: null,
  osId: "ubuntu",
  osVersion: "24.04",
  ip: null,
  lastSeenAt: null,
  archivedAt: null,
  reported: true,
  agents: [],
  vulns: zero,
  images: noImg,
  duplicateOf: null,
  mergedInto: null,
  rebootRequired: false,
  ...o,
});
const f = (o: Partial<MachineFilters> = {}): MachineFilters => ({
  q: null,
  status: null,
  os: null,
  critical: false,
  kev: false,
  archived: false,
  ...o,
});
const names = (rows: MachineRow[]) => rows.map((r) => r.hostname);

test("junk params are ignored", () => {
  expect(
    parseMachineFilters({ status: "bogus", os: "", critical: "yes", q: ["web", "db"] }),
  ).toEqual({
    q: "web",
    status: null,
    os: null,
    critical: false,
    kev: false,
    archived: false,
  });
});
test("valid params are parsed", () => {
  expect(
    parseMachineFilters({ status: "stale", os: "debian", critical: "1", kev: "1", archived: "1" }),
  ).toEqual({
    q: null,
    status: "stale",
    os: "debian",
    critical: true,
    kev: true,
    archived: true,
  });
});
test("search matches hostname, label, OS and IP fragments; nulls are safe", () => {
  const rows = [
    m({ hostname: "db-primary", ip: "10.0.1.12" }),
    m({ hostname: "edge", label: null, osId: null, ip: null }),
  ];
  expect(names(filterMachines(rows, f({ q: "10.0.1" })))).toEqual(["db-primary"]);
  expect(names(filterMachines(rows, f({ q: "EDGE" })))).toEqual(["edge"]);
  expect(names(filterMachines(rows, f({ q: "ubuntu 24" })))).toEqual(["db-primary"]);
  expect(
    names(filterMachines([m({ hostname: "x", label: "Billing box" })], f({ q: "billing" }))),
  ).toEqual(["x"]);
});
test("status and os filters", () => {
  const rows = [
    m({ hostname: "a", agents: [a("online")] }),
    m({ hostname: "b", osId: "debian", agents: [a("stale")] }),
  ];
  expect(names(filterMachines(rows, f({ status: "online" })))).toEqual(["a"]);
  expect(names(filterMachines(rows, f({ os: "debian" })))).toEqual(["b"]);
});
test("critical filter counts packages or running images", () => {
  const rows = [
    m({ hostname: "a", vulns: { ...zero, critical: 1 } }),
    m({ hostname: "b", images: { ...noImg, critical: 2 } }),
    m({ hostname: "c" }),
  ];
  expect(names(filterMachines(rows, f({ critical: true })))).toEqual(["a", "b"]);
});
test("kev filter counts packages or running images", () => {
  const rows = [
    m({ hostname: "a", vulns: { ...zero, kev: 1 } }),
    m({ hostname: "b", images: { ...noImg, kev: 1 } }),
    m({ hostname: "c" }),
  ];
  expect(names(filterMachines(rows, f({ kev: true })))).toEqual(["a", "b"]);
});
test("archived hidden unless asked", () => {
  const rows = [m({ hostname: "a" }), m({ hostname: "b", archivedAt: "2026-01-01T00:00:00Z" })];
  expect(names(filterMachines(rows, f({})))).toEqual(["a"]);
  expect(names(filterMachines(rows, f({ archived: true })))).toEqual(["a", "b"]);
});
test("filtering keeps input order", () => {
  expect(names(filterMachines([m({ hostname: "b" }), m({ hostname: "a" })], f()))).toEqual([
    "b",
    "a",
  ]);
});
test("summary ignores archived", () => {
  expect(
    summarizeMachines([
      m({ vulns: { ...zero, critical: 1 } }),
      m({ archivedAt: "2026-01-01T00:00:00Z" }),
    ]),
  ).toEqual({
    machines: 1,
    withCritical: 1,
    archived: 1,
  });
});

test("summary text: plural, singular, and the critical suffix", () => {
  expect(machinesSummaryText({ machines: 12, withCritical: 0 })).toBe("12 machines");
  expect(machinesSummaryText({ machines: 1, withCritical: 0 })).toBe("1 machine");
  expect(machinesSummaryText({ machines: 0, withCritical: 0 })).toBe("0 machines");
  expect(machinesSummaryText({ machines: 12, withCritical: 3 })).toBe(
    "12 machines · 3 with critical vulnerabilities",
  );
  expect(machinesSummaryText({ machines: 1, withCritical: 1 })).toBe(
    "1 machine · 1 with critical vulnerabilities",
  );
});
test("image tooltip names vulnerabilities, running images and critical", () => {
  expect(imageVulnsTitle({ vulns: 14, images: 3, critical: 2, kev: 0 })).toBe(
    "14 vulnerabilities in 3 running images · 2 critical",
  );
  expect(imageVulnsTitle({ vulns: 1, images: 1, critical: 0, kev: 0 })).toBe(
    "1 vulnerability in 1 running image · 0 critical",
  );
});
