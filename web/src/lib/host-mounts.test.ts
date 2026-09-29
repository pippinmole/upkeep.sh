/// <reference types="bun" />

// The dashboard's `docker run` snippet and agent/docker-compose.example.yml
// must mount the host filesystem the same way, or one of the two docs
// would drift into an insecure recursive mount. This checks the docker run
// flags (HOST_MOUNTS) against the bind volumes in the compose file.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { HOST_MOUNTS } from "@/lib/host-mounts";

const composePath = join(import.meta.dir, "../../../agent/docker-compose.example.yml");
const compose = readFileSync(composePath, "utf8");

// Parse the long-form bind volumes (source/target/read_only, recursive)
// from the volumes: block, as `src=…,dst=…,readonly[,bind-recursive=disabled]`
// strings, in file order.
function composeBindMounts(yaml: string): string[] {
  const lines = yaml.split("\n");
  const out: string[] = [];
  let cur: { src?: string; dst?: string; ro?: boolean; rec?: string } | null = null;
  const flush = () => {
    if (cur?.src && cur.dst) {
      let s = `--mount type=bind,src=${cur.src},dst=${cur.dst}`;
      if (cur.ro) s += ",readonly";
      if (cur.rec) s += `,bind-recursive=${cur.rec}`;
      out.push(s);
    }
    cur = null;
  };
  for (const raw of lines) {
    const line = raw.trim();
    if (line === "- type: bind") {
      flush();
      cur = {};
      continue;
    }
    if (line.startsWith("- ") && cur) flush();
    if (!cur) continue;
    const src = line.match(/^source:\s*(\S+)$/);
    if (src) cur.src = src[1];
    const dst = line.match(/^target:\s*(\S+)$/);
    if (dst) cur.dst = dst[1];
    if (/^read_only:\s*true$/.test(line)) cur.ro = true;
    const rec = line.match(/^recursive:\s*(\S+)$/);
    if (rec) cur.rec = rec[1];
  }
  flush();
  return out;
}

describe("host filesystem mount", () => {
  test("docker run flags match the compose bind mounts", () => {
    const composeMounts = composeBindMounts(compose);
    expect(composeMounts).toEqual(HOST_MOUNTS);
  });

  test("the / bind is non-recursive (no socket exposure)", () => {
    const root = HOST_MOUNTS.find((m) => /(^|,)dst=\/host(,|$)/.test(m));
    expect(root).toContain("src=/,");
    expect(root).toContain("bind-recursive=disabled");
    // A plain recursive `-v /:/host:ro` must never come back.
    expect(HOST_MOUNTS.join("\n")).not.toContain("-v /:/host");
  });

  test("nothing under /run itself is bound (the sockets live there)", () => {
    for (const m of HOST_MOUNTS) {
      expect(m).not.toMatch(/dst=\/host\/run(,|$)/);
      expect(m).not.toMatch(/src=\/run(,|$)/);
    }
  });
});
