import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  reactCompiler: true,
  // We self-host via Docker on Dokploy, not Vercel — standalone output
  // produces a minimal server bundle (only the deps actually used) so
  // the production image doesn't need the full node_modules tree.
  output: "standalone",
};

export default nextConfig;
