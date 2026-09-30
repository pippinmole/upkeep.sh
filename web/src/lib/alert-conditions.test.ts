import { describe, expect, test } from "bun:test";

import { describeCondition, PROPERTIES, validateCondition } from "./alert-conditions";
import vectors from "./alert-conditions.vectors.json";

type Vector = {
  name: string;
  input: unknown;
  ok: boolean;
  normalized?: unknown;
  field?: string;
};

// The same vectors as server/internal/alerting TestConditionVectors: both
// validators must agree on every one.
describe("validateCondition matches the Go validator", () => {
  for (const v of vectors.vectors as Vector[]) {
    test(v.name, () => {
      const r = validateCondition(v.input);
      if (v.ok) {
        expect(r).toEqual({ ok: true, condition: v.normalized as never });
        // Idempotent.
        if (r.ok) expect(validateCondition(r.condition)).toEqual(r);
      } else {
        expect(r.ok).toBe(false);
        if (!r.ok) expect(r.field).toBe(v.field!);
      }
    });
  }
});

test("the catalogue is loaded", () => {
  expect(PROPERTIES.map((p) => p.key)).toContain("listening_port");
});

test("describeCondition", () => {
  expect(
    describeCondition({
      property: "listening_port",
      operator: "in",
      value: [22],
      options: { protocol: "tcp", bind: "non_loopback" },
    }),
  ).toBe("Listening port is one of 22 (TCP, any address except loopback)");
  expect(
    describeCondition({ property: "host_not_seen", operator: "for_more_than", value: 120 }),
  ).toBe("Host not seen for more than 2 hours");
  expect(
    describeCondition({
      property: "vulnerability",
      operator: "severity_at_least",
      value: "high",
      options: { source: "images" },
    }),
  ).toBe("Vulnerability severity is at least high (container images)");
  expect(
    describeCondition({
      property: "package_installed",
      operator: "installed",
      value: ["a", "b", "c", "d"],
    }),
  ).toBe("Package is installed a, b, c +1 more");
  expect(describeCondition({ property: "reboot_required", operator: "is_true" })).toBe(
    "Reboot required is required",
  );
});
