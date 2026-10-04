// Per-credential rate limit for /api/mcp (docs/MCP.md#security-notes): a
// fixed one-minute window per key, in memory, since the web app runs as one
// process. Generous enough for an agent loop; it bounds a client stuck in
// one.

export type RateLimiter = {
  // Counts one call for the key: true if it's within the limit.
  hit: (key: string) => boolean;
};

export function createRateLimiter(opts: {
  limit: number;
  windowMs: number;
  now?: () => number;
}): RateLimiter {
  const now = opts.now ?? Date.now;
  const windows = new Map<string, { start: number; count: number }>();
  let lastSweep = now();
  return {
    hit(key) {
      const t = now();
      // Drop finished windows now and then so idle credentials don't pile up.
      if (t - lastSweep >= opts.windowMs) {
        for (const [k, w] of windows) if (t - w.start >= opts.windowMs) windows.delete(k);
        lastSweep = t;
      }
      const w = windows.get(key);
      if (!w || t - w.start >= opts.windowMs) {
        windows.set(key, { start: t, count: 1 });
        return true;
      }
      w.count++;
      return w.count <= opts.limit;
    },
  };
}

export const MCP_CALLS_PER_MINUTE = 120;

export const mcpRateLimiter = createRateLimiter({ limit: MCP_CALLS_PER_MINUTE, windowMs: 60_000 });
