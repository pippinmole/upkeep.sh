/// <reference types="bun" />

import { expect, test } from "bun:test";

import { isTabActive, tabs } from "./nav-config";

test("Machines is active on home and on machine pages only", () => {
  const m = tabs[0];
  expect(isTabActive("/dashboard", m)).toBe(true);
  expect(isTabActive("/dashboard/hosts/abc/vulnerabilities", m)).toBe(true);
  expect(isTabActive("/dashboard/vulnerabilities", m)).toBe(false); // "/dashboard" must match exactly
});

test("Settings is active under settings and agents", () => {
  const s = tabs.find((t) => t.title === "Settings")!;
  expect(isTabActive("/dashboard/settings/members", s)).toBe(true);
  expect(isTabActive("/dashboard/agents", s)).toBe(true);
  expect(isTabActive("/dashboard/settingsx", s)).toBe(false);
});

test("tab order", () => {
  expect(tabs.map((t) => t.title)).toEqual([
    "Machines",
    "Vulnerabilities",
    "Images",
    "Alerts",
    "Reports",
    "Settings",
  ]);
});
