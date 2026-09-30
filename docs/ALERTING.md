# Alerting: condition rules and stateful alerts

Status: MVP, migration 0024. Replaces the event rules of migration 0009
(`event_types` + severity / KEV / finding-kind filters + a dedup window).
Channels, the delivery pipeline (`notifications`, `notification_deliveries`,
`alert_deliver`, digests) and the Notifier interface are unchanged.

## Why one model

The 0009 rules subscribed to *events* (`finding.opened`, `agent.stale`, …)
and deduplicated them with a time window. That can't express "port 22 is
listening" (a *state*, not an event), and a second, parallel rule system
next to it would give users two overlapping ways to alert on the same
vulnerability. So every rule is now a **condition over a host's current
state**, evaluated into **stateful alert instances**. The old event rules map
onto conditions (`vulnerability`, `host_not_seen`), and nothing is deployed,
so the migration is destructive: existing event rules are dropped.

## User stories

1. As an operator I want to be told when a host starts listening on SSH
   (22/tcp) on a non-loopback address, without having to set anything up,
   so the default install already watches the most common exposure.
2. I want to build my own rules from a list of host properties (listening
   ports, installed packages, OS, reboot required, vulnerabilities, host not
   seen, collector failures), without writing queries.
3. I want each rule to cover all hosts, including future ones, or only
   hosts I pick.
4. I want a rule to notify the channels I pick (email, webhook, ntfy) once
   when it starts firing and, if I ask, once when it resolves, and never
   once per snapshot.
5. I want to see what is firing now, what fired before, and which hosts
   currently have firing alerts.
6. I want to disable a rule without deleting it, and to know that
   disabling or editing it won't send a flood of "resolved" messages.

## Rule model

`alert_rules` (Next.js-owned, like channels):

| column | meaning |
|---|---|
| `name`, `enabled` | as before |
| `condition jsonb` | `{property, operator, value?, options?}` (below) |
| `host_ids uuid[]` | scope: `NULL` = all hosts, including future ones; otherwise these hosts |
| `notify_on_resolve` | also send when an alert resolves (default on) |
| `digest`, `digest_interval_seconds`, `last_digest_at` | as before: batch notifications per interval |
| `default_key` | set on seeded default rules (`ssh_port_22`) so seeding is idempotent |
| channels | `alert_rule_channels`, as before. **Zero channels is allowed**: the rule then only shows alerts in the dashboard (the seeded default starts like this) |

### Condition

```json
{"property": "listening_port", "operator": "in", "value": [22],
 "options": {"protocol": "tcp", "bind": "non_loopback"}}
```

- `property`: a key from the catalogue below.
- `operator`: one of the property's operators.
- `value`: typed by the operator: none, a list of ints (ports), a list of
  strings, an enum value, or an int.
- `options`: property qualifiers (select fields with defaults).

The catalogue lives in Go (`server/internal/alerting/catalog.go`). Go
validates and normalises conditions (`alerting.Validate`: sorted and
de-duplicated lists, lower-cased identifiers, option defaults filled in) and
refuses to evaluate an invalid one. The dashboard gets the same catalogue
as generated JSON (`web/src/lib/alert-properties.json`, written by
`go test ./internal/alerting -update` and checked by a golden test, like
`notifier-types.json`) and validates with a generic, schema-driven
validator. A shared vector file (`web/src/lib/alert-conditions.vectors.json`)
of valid and invalid conditions with their normalised form is run by both
the Go and the Bun tests, so the two validators can't drift apart.

**Adding a property**: add it to the catalogue, add its SQL evaluator in
`server/internal/store/alertrules_eval.go` (a test fails if a property has
none), regenerate the JSON, and add vectors. The UI renders it with no
other change.

## MVP property catalogue

Every property is OS-neutral: it reads the normalised tables every agent
fills (`host_listeners`, `host_software`, `hosts.os_*`, `snapshots`,
`findings`), not Debian-specific files.

| property | operators | value | options | subject (one alert per) |
|---|---|---|---|---|
| `listening_port` | `in` (is one of), `not_in` (is not one of: an allowlist) | ports, 1–65535, ≤ 50 | `protocol`: tcp / udp / any (default tcp); `bind`: non_loopback (all interfaces or a specific non-loopback address, default) / all_interfaces (0.0.0.0 or ::) / loopback / any | `tcp/22` (IPv4 and IPv6 sockets of the same port are one alert; the addresses are in the details) |
| `package_installed` | `installed`, `not_installed` | package names, ≤ 50 | none | package name. Matches the package *name* in any ecosystem (deb today; rpm, apk, Windows programs later) |
| `os` | `in`, `not_in` | OS ids or families (`ubuntu`, `debian`, `linux`, `windows`), ≤ 20 | none | host. Matches `hosts.os_id` or `hosts.os_family`; a host whose OS is unknown never matches |
| `reboot_required` | `is_true` | none | none | host. From the newest snapshot whose `reboot_required` collector was ok (a failed collector never resolves it) |
| `vulnerability` | `severity_at_least` (low / medium / high / critical), `kev` (known exploited) | enum / none | `source`: any / packages / images (default any) | finding (`findings.dedup_key`); the notification carries the finding object |
| `host_not_seen` | `for_more_than` | minutes, 5–43200 | none | host. From `hosts.last_seen_at`; a host never seen doesn't fire |
| `collector_failed` | `any`, `in` | collector names, ≤ 30 | none | collector. From the newest snapshot's `collector_status` (`status = "error"`) |

"Unknown" never resolves an alert: failed collectors keep their previous
ranges (PROTOCOL.md "a failed collector is never a removal"), so a listening
port alert stays firing while `tcp_listeners` is failing, and
`reboot_required` reads the newest snapshot where its collector was ok.

## Evaluation

Level-triggered reconciliation in the **worker**, job `alert_rules_evaluate`
(queue `alerts`):

```
ingest (snapshot tx)        ──InsertTx──> alert_rules_evaluate {host_id}
reconcile_host (findings tx, when findings changed) ──> alert_rules_evaluate {host_id}
dashboard (rule created / edited / enabled / disabled / deleted) ──> alert_rules_evaluate {}
periodic, every 1m          ──> alert_rules_evaluate {}  (all hosts: time-based rules, safety net)

alert_rules_evaluate (advisory-locked):
  for each rule (of the host's user, or of every user):
    desired = property evaluator(condition, hosts in scope, not archived)   -- one SQL query per rule
    firing  = alert_instances WHERE rule AND state = 'firing' (for those hosts)
    plan    = alerting.Diff(firing, desired)
    new match          -> insert instance (firing) + alert_events 'alert.firing'
    still matching     -> refresh title / details / last_matched_at (no event)
    no longer matching -> resolve; 'alert.resolved' event only if reason = cleared
                          and the rule has notify_on_resolve
  -> alert_evaluate (InsertTx) when events were written
alert_evaluate: events -> notifications (immediate, or digest items) -> alert_deliver
```

Why the worker, not inline in ingest: ingest stays fast and never waits on
alerting (ARCHITECTURE.md); vulnerability findings are produced by the
worker after matching anyway; time-based rules (`host_not_seen`) need a
clock-driven pass; and one code path (evaluate a set of hosts) serves all
triggers. The snapshot's job is inserted in the snapshot transaction, so
latency after a push is about a second. The pass is idempotent, so a lost or
duplicated trigger only delays (≤ 1 minute) or repeats a no-op.

### State machine

Instances are keyed by **(rule, host, subject)**; subject is `''` for
host-level properties. Each firing episode is its own row, so the table is
also the history.

```
(none) --match--> firing --no longer matches--> resolved(cleared)          [notifies if notify_on_resolve]
                   |      --rule condition edited, no longer matches--> resolved(rule_changed)  [silent]
                   |      --rule disabled--> resolved(rule_disabled)                           [silent]
                   |      --rule deleted--> resolved(rule_deleted)                             [silent]
                   |      --host left the rule's scope--> resolved(out_of_scope)               [silent]
                   |      --host archived--> resolved(host_archived)                           [silent]
resolved --match again--> a new firing instance (new row)
```

- **Dedup** is the state machine: at most one firing instance per key
  (partial unique index), and a notification is only created on a
  transition, never per snapshot.
- Silent resolutions are bookkeeping, not news: turning a rule off must not
  send "resolved" for everything it covered.
- Deleting a rule keeps its instances (`rule_id` → NULL, the name is kept
  on the instance) so history survives; the next pass resolves them.
- Deleting a host deletes its instances.
- A new or edited rule fires for everything that already matches (like any
  level-triggered alerting): the first notification after creating a
  vulnerability rule can list many findings, which is what digests and the
  200-events-per-notification split are for.
- Flapping (a port that opens and closes every push) fires and resolves
  each time. Follow-up: a "for at least N minutes" hold.
- Resolved instances are pruned after 90 days (`alert_prune`, the
  delivery log's retention).

## Notifications

`notify.Event` gains an `alert` object and two event types,
`alert.firing` and `alert.resolved` (payload version 2, WEBHOOKS.md). The
event also carries `host`, and for `vulnerability` rules the `finding`
object as before. ntfy and email titles come from `render.Title`:
`Port 22/tcp is listening on web-1`, `Resolved: Port 22/tcp is listening on
web-1`, `KEV CVE-2024-3094 in xz-utils on web-1`. One notification per rule
per evaluation pass (or per digest interval), split at 200 events.

The `finding.*` / `agent.*` event types, `alert_dedup`, the dedup window
and the `agent_health` job are gone: `vulnerability` and `host_not_seen`
rules replace them.

## UI

- **Settings → Alert rules** (`/dashboard/settings/alert-rules`): rules
  table (name, condition in words, scope, channels, delivery, firing count,
  enabled) with create / edit / enable / disable / delete. The rule dialog
  is rendered from the catalogue: property, then operator, then a value
  input by type, then options.
- **Alerts** (`/dashboard/alerts`): the alerts list, firing and resolved,
  server-driven DataTable (search, state / rule / host facets, paging),
  firing first, then newest (a sort rather than a default filter, so
  "clear filters" shows everything). `?host=` is also the link in
  notifications. Each row links to its host. The **Delivery log** tab
  stays.
- **Hosts**: a firing-alerts count column on the Hosts table, a badge on
  the host page header linking to the host's alerts, and the sidebar's
  Alerts badge counts firing alerts.

## Default rules

A SQL function `seed_default_alert_rules(workspace)` inserts the defaults,
keyed by `default_key` so it never duplicates. An `AFTER INSERT` trigger on
`workspaces` calls it, and the migration calls it for the existing
workspace. MVP default: **"SSH listening (port 22)"**:
`listening_port in [22]`, tcp, non-loopback, all hosts, no channels (it
shows in the dashboard; add a channel to be notified). A deleted default
rule isn't recreated.

## Ownership

Per workspace, like hosts and channels (migration 0023, docs/MEMBERS.md):
`alert_rules.workspace_id`, `alert_instances.workspace_id` and
`alert_events.workspace_id`. Where ownership lives:

- SQL: the columns above and `seed_default_alert_rules(workspace)` +
  its trigger on `workspaces` (migration 0024).
- Go: `store/alertrules.go` scopes rules to hosts through
  `alertRuleHostsSQL` (the only place joining a rule's workspace to hosts).
- Web: `web/src/lib/queries-alerts.ts` (reads) and
  `web/src/app/dashboard/alert-rule-actions.ts` (writes); every statement
  filters by the viewer's workspace id. Rule actions need the admin role
  (`requireAdmin`); members get read-only pages.

## Out of scope (follow-ups)

Recorded in [tasks/phase-1-alerting.md](tasks/phase-1-alerting.md):

- Host tags/labels as a rule scope. Hosts have only a display label today
  (`hosts.label`), not tags, so scope is all hosts or picked hosts.
- Hold / flap damping ("firing for at least N minutes"), and re-notify
  while still firing (reminders).
- Acknowledge / silence / snooze an alert; maintenance windows.
- More properties: service running / stopped, local user exists or is
  admin, Docker container running / exposed port, public IP changed,
  EPSS above N, package version comparisons, exposure classification
  (Phase 1.6).
- Per-rule severity (info / warning / critical) for routing and ntfy
  priority.
- Alert detail page with the notifications sent for it.
