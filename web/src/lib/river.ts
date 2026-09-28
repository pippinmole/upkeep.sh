import type { PoolClient } from "pg";

// Enqueue a River job from Node with plain SQL, the way River's non-Go
// clients (riverqueue-python / -ruby) do: a river_job row in state
// 'available' is picked up by the worker's next fetch poll (~1 s). Used by
// "Send test" (alert_deliver, args AlertDeliverArgs) and the report "Send
// now" button (report_send_now); each kind and its args must match the
// worker's args type in server/internal/jobs. River's schema is vendored as
// migration 0006, so a River upgrade that changed it would show up there.
async function insertJob(
  client: PoolClient,
  kind: string,
  args: object,
  queue: string,
  maxAttempts: number,
): Promise<void> {
  await client.query(
    `INSERT INTO river_job (kind, args, queue, max_attempts, priority, state, scheduled_at)
     VALUES ($1, $2::jsonb, $3, $4, 1, 'available', now())`,
    [kind, JSON.stringify(args), queue, maxAttempts],
  );
  // River also listens for inserts on "<schema>.river_insert"; the
  // notification only shortens the wait.
  await client.query(`SELECT pg_notify(current_schema() || '.river_insert', $1)`, [
    JSON.stringify({ queue }),
  ]);
}

export async function enqueueAlertDelivery(
  client: PoolClient,
  deliveryId: string,
  maxAttempts: number,
): Promise<void> {
  await insertJob(client, "alert_deliver", { delivery_id: deliveryId }, "alerts", maxAttempts);
}

// "Send now": a real report run for one schedule (trigger 'manual'). The
// worker builds, stores and delivers it like a scheduled run and sets
// last_run_at, without touching next_run_at.
export async function enqueueReportSendNow(client: PoolClient, scheduleId: string): Promise<void> {
  await insertJob(client, "report_send_now", { schedule_id: scheduleId }, "alerts", 3);
}
