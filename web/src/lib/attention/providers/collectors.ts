import { activeHost } from "../owner";
import { hostHref, nameList, plural } from "../rank";
import type { AttentionItem, AttentionProvider } from "../types";

// From each host's newest snapshot's collector_status:
// - host_mount = error: the agent container can reach host unix sockets
//   (docker.sock, containerd, D-Bus) through a recursive / mount. Anything
//   that can connect() to them controls the host. Its own, critical item.
// - any other collector = error: that section is unknown, not empty, so
//   findings and alerts that depend on it may be stale. `skipped` (not
//   applicable) is not a failure.

export type CollectorHost = {
  id: string;
  name: string;
  socketsExposed: boolean;
  failed: string[]; // collectors in error, host_mount aside
};

// One LATERAL per host on snapshots_host_collected_idx, as the estate query.
const SQL = `
  SELECT h.id, coalesce(h.label, h.hostname) AS name,
         coalesce(s.collector_status->'host_mount'->>'status' = 'error', false) AS sockets_exposed,
         ARRAY(SELECT e.key FROM jsonb_each(s.collector_status) e
               WHERE e.value->>'status' = 'error' AND e.key <> 'host_mount'
               ORDER BY e.key) AS failed
  FROM hosts h
  JOIN LATERAL (
    SELECT sn.collector_status FROM snapshots sn
    WHERE sn.host_id = h.id
    ORDER BY sn.collected_at DESC LIMIT 1
  ) s ON jsonb_typeof(s.collector_status) = 'object'
  WHERE ${activeHost("h")}
    AND EXISTS (SELECT 1 FROM jsonb_each(s.collector_status) e WHERE e.value->>'status' = 'error')
  ORDER BY lower(coalesce(h.label, h.hostname)), h.id`;

export const collectors: AttentionProvider<CollectorHost[]> = {
  key: "collectors",
  load: async (ctx) =>
    (
      await ctx.query<{ id: string; name: string; sockets_exposed: boolean; failed: string[] }>(SQL)
    ).map((r) => ({
      id: r.id,
      name: r.name,
      socketsExposed: r.sockets_exposed,
      failed: r.failed,
    })),
  map: (hosts) => {
    const items: AttentionItem[] = [];
    const exposed = hosts.filter((h) => h.socketsExposed);
    if (exposed.length > 0) {
      items.push({
        key: "host-sockets",
        severity: "critical",
        tone: "danger",
        icon: "socket",
        title: `Host sockets reachable from the agent on ${plural(exposed.length, "host", "hosts")}`,
        subject: nameList(exposed.map((h) => h.name)),
        why: "Whatever can connect to docker.sock controls the host: mount / non-recursively.",
        count: exposed.length,
        href: hostHref(exposed.length, exposed[0].id, "/dashboard/hosts"),
      });
    }
    const failing = hosts.filter((h) => h.failed.length > 0);
    if (failing.length > 0) {
      items.push({
        key: "collectors",
        severity: "medium",
        tone: "warning",
        icon: "collector",
        title:
          failing.length === 1 ? "Collectors failing on a host" : "Collectors failing on hosts",
        subject: nameList(failing.map((h) => `${h.name} (${h.failed.join(", ")})`)),
        why: "Those sections are unknown, not empty: findings and alerts based on them may be stale.",
        count: failing.length,
        href: hostHref(failing.length, failing[0].id, "/dashboard/hosts"),
      });
    }
    return items;
  },
};
