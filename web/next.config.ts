import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  reactCompiler: true,
  // We self-host via Docker on Dokploy, not Vercel — standalone output
  // produces a minimal server bundle (only the deps actually used) so
  // the production image doesn't need the full node_modules tree.
  output: "standalone",
  // Turbopack's dev filesystem cache (.next/dev/cache/turbopack, default
  // on since Next 16.1) was found to serve stale compiled output across
  // both a Docker bind mount AND a native run — edits stopped showing up
  // at all, even after a full dev-server restart, until this was disabled
  // and the stale .next dir removed. New/experimental feature, don't
  // re-enable without confirming edits actually hot-reload again first.
  experimental: {
    turbopackFileSystemCacheForDev: false,
  },
};

export default nextConfig;
