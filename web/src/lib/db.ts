import { Pool } from "pg";

// The dashboard reads Postgres directly rather than proxying through the
// Go ingest API — the API's job is the agent protocol and background
// workers (matching, scanning, alerting), not serving dashboard queries.
declare global {
  // eslint-disable-next-line no-var
  var _swPool: Pool | undefined;
}

export const pool =
  global._swPool ??
  new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 5,
  });

if (process.env.NODE_ENV !== "production") {
  global._swPool = pool;
}
