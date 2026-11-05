/// <reference types="bun" />

import { expect, test } from "bun:test";
import { type AgentStatus, collectorLabel, hasNoActiveAgent, type MachineAgent, machineStatus } from "./machines";

const a = (status: AgentStatus, mode: MachineAgent["mode"] = "local", name = "a1"): MachineAgent => ({
  id: name,
  name,
  mode,
  status,
});

test("status: any online wins", () => expect(machineStatus([a("stale"), a("online", "ssh")])).toBe("online"));
test("status: active but none online is stale", () => expect(machineStatus([a("never"), a("stale")])).toBe("stale"));
test("status: all revoked is stale with no active agent", () => {
  expect(machineStatus([a("revoked")])).toBe("stale");
  expect(hasNoActiveAgent([a("revoked")])).toBe(true);
});
test("status: only never-reported agents is never", () => expect(machineStatus([a("never")])).toBe("never"));
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
