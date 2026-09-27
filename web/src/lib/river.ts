import type { PoolClient } from "pg";

// Enqueue a River job from Node with plain SQL, the way River's non-Go
// clients (riverqueue-python / -ruby) do: a river_job row in state
// 'available' is picked up by the worker's next fetch poll (~1 s). Only
// used for the "send test" button; the kind and args must match
// server/internal/jobs/alerting.go (AlertDeliverArgs). River's schema is
// vendored as migration 0006, so a River upgrade that changed it would
// show up there.
export async function enqueueAlertDelivery(
  client: PoolClient,
  deliveryId: string,
  maxAttempts: number,
): Promise<void> {
  await client.query(
    `INSERT INTO river_job (kind, args, queue, max_attempts, priority, state, scheduled_at)
     VALUES ('alert_deliver', $1::jsonb, 'alerts', $2, 1, 'available', now())`,
    [JSON.stringify({ delivery_id: deliveryId }), maxAttempts],
  );
  // River also listens for inserts on "<schema>.river_insert"; the
  // notification only shortens the wait.
  await client.query(`SELECT pg_notify(current_schema() || '.river_insert', $1)`, [
    JSON.stringify({ queue: "alerts" }),
  ]);
}
