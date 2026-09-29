/// <reference types="bun" />

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import example from "@/lib/report-snapshot.example.json";
import { POST } from "./route";

const SECRET = "test-render-secret";
const INTERNAL = "http://web:3000";
const ENV_KEYS = ["SW_INTERNAL_RENDER_SECRET", "SW_WEB_INTERNAL_URL", "BETTER_AUTH_URL"] as const;
const saved: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  process.env.SW_INTERNAL_RENDER_SECRET = SECRET;
  process.env.SW_WEB_INTERNAL_URL = INTERNAL;
  process.env.BETTER_AUTH_URL = "https://upkeep.example.com";
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
});

function req(
  opts: {
    host?: string;
    auth?: string | null;
    body?: unknown;
    headers?: Record<string, string>;
  } = {},
): Request {
  const headers = new Headers(opts.headers);
  headers.set("host", opts.host ?? "web:3000");
  const auth = opts.auth === undefined ? `Bearer ${SECRET}` : opts.auth;
  if (auth !== null) headers.set("authorization", auth);
  headers.set("content-type", "application/json");
  const body =
    typeof opts.body === "string"
      ? opts.body
      : JSON.stringify(
          opts.body ?? {
            snapshot: example,
            report_url: "https://upkeep.example.com/dashboard/reports/1",
          },
        );
  return new Request(`http://${opts.host ?? "web:3000"}/api/internal/render/report`, {
    method: "POST",
    headers,
    body,
  });
}

describe("POST /api/internal/render/report", () => {
  test("404 when the secret is unset", async () => {
    delete process.env.SW_INTERNAL_RENDER_SECRET;
    expect((await POST(req())).status).toBe(404);
    process.env.SW_INTERNAL_RENDER_SECRET = "";
    expect((await POST(req())).status).toBe(404);
  });

  test("401 on a wrong or missing secret", async () => {
    expect((await POST(req({ auth: "Bearer nope" }))).status).toBe(401);
    expect((await POST(req({ auth: SECRET }))).status).toBe(401);
    expect((await POST(req({ auth: null }))).status).toBe(401);
    expect((await POST(req({ auth: "Bearer " }))).status).toBe(401);
  });

  test("404 on the public host, even with the secret", async () => {
    expect((await POST(req({ host: "upkeep.example.com" }))).status).toBe(404);
    // Through the public proxy with a forged Host.
    const forwarded = req({ headers: { "x-forwarded-host": "upkeep.example.com" } });
    expect((await POST(forwarded)).status).toBe(404);
  });

  test("404 without an internal URL, or when it is the public host", async () => {
    delete process.env.SW_WEB_INTERNAL_URL;
    expect((await POST(req())).status).toBe(404);
    process.env.SW_WEB_INTERNAL_URL = "https://upkeep.example.com";
    expect((await POST(req({ host: "upkeep.example.com" }))).status).toBe(404);
  });

  test("400 on a bad body", async () => {
    expect((await POST(req({ body: "not json" }))).status).toBe(400);
    expect((await POST(req({ body: [] }))).status).toBe(400);
    expect((await POST(req({ body: { report_url: null } }))).status).toBe(400);
    const v2 = { snapshot: { ...example, schema_version: 2 }, report_url: null };
    expect((await POST(req({ body: v2 }))).status).toBe(400);
    expect((await POST(req({ body: { snapshot: example } }))).status).toBe(400);
    expect((await POST(req({ body: { snapshot: example, report_url: 3 } }))).status).toBe(400);
    const js = { snapshot: example, report_url: "javascript:alert(1)" };
    expect((await POST(req({ body: js }))).status).toBe(400);
  });

  test("500 when the snapshot can't be rendered", async () => {
    const res = await POST(req({ body: { snapshot: { schema_version: 1 }, report_url: null } }));
    expect(res.status).toBe(500);
  });

  test("200 with subject, html and text", async () => {
    const res = await POST(req());
    expect(res.status).toBe(200);
    const out = (await res.json()) as { subject: string; html: string; text: string };
    expect(out.subject).toBe(
      "[upkeep.sh] Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting",
    );
    expect(out.html).toContain("<html");
    expect(out.html).toContain("https://upkeep.example.com/dashboard/reports/1");
    expect(out.text).toContain("Coverage gaps");
  });

  test("200 with a null report URL", async () => {
    const res = await POST(req({ body: { snapshot: example, report_url: null } }));
    expect(res.status).toBe(200);
  });
});
