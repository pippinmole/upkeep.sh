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
  // Keep old links working. "Notifications" was split into Alerts (rules,
  // delivery log) and Settings -> Notification settings, which became
  // Settings -> Channels, with report schedules moved to top-level Reports.
  // Specific sources first.
  async redirects() {
    return [
      {
        source: "/dashboard/settings/notifications/reports/:scheduleId",
        destination: "/dashboard/reports/schedules/:scheduleId",
        permanent: true,
      },
      {
        source: "/dashboard/settings/notifications",
        destination: "/dashboard/settings/channels",
        permanent: true,
      },
      {
        source: "/dashboard/reports/schedules",
        destination: "/dashboard/reports",
        permanent: true,
      },
      {
        source: "/dashboard/notifications/channels",
        destination: "/dashboard/settings/channels",
        permanent: true,
      },
      {
        source: "/dashboard/notifications/:path*",
        destination: "/dashboard/alerts/:path*",
        permanent: true,
      },
    ];
  },
};

export default nextConfig;
