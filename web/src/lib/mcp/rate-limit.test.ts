/// <reference types="bun" />

import { describe, expect, test } from "bun:test";

import { createRateLimiter } from "./rate-limit";

describe("createRateLimiter", () => {
  test("allows the limit per window, per key, then resets", () => {
    let t = 0;
    const limiter = createRateLimiter({ limit: 3, windowMs: 60_000, now: () => t });
    expect([1, 2, 3, 4].map(() => limiter.hit("a"))).toEqual([true, true, true, false]);
    expect(limiter.hit("b")).toBe(true);
    t = 59_999;
    expect(limiter.hit("a")).toBe(false);
    t = 60_000;
    expect(limiter.hit("a")).toBe(true);
  });

  test("idle keys are swept and start fresh", () => {
    let t = 0;
    const limiter = createRateLimiter({ limit: 1, windowMs: 1000, now: () => t });
    expect(limiter.hit("a")).toBe(true);
    expect(limiter.hit("a")).toBe(false);
    t = 5000;
    expect(limiter.hit("b")).toBe(true);
    expect(limiter.hit("a")).toBe(true);
  });
});
