# Webhooks

A **webhook** notification channel receives an HTTPS `POST` of a JSON
document for every notification a rule or a report schedule sends to it
(and for "Send test"). Channels are configured under
**Dashboard → Settings → Channels**, report schedules under **Dashboard →
Reports**, and the rules that send to
them under **Dashboard → Alerts** (which also holds the delivery log); the
pipeline behind them is described in
[ARCHITECTURE.md § Alerting](ARCHITECTURE.md#alerting). Scheduled reports
have their own body shape, see [Report notifications](#report-notifications).

## Request

```
POST /your/path HTTP/1.1
Content-Type: application/json
User-Agent: upkeep.sh-webhook/1
X-Upkeep-Kind: alert                       # alert | digest | test | report
X-Upkeep-Delivery: 4b579242-c8a0-...       # same value on every retry of this delivery
X-Upkeep-Timestamp: 1790512453             # unix seconds, when this attempt was signed
X-Upkeep-Signature: v1=5d41402abc4b2a76... # see "Verifying the signature"
```

Respond with any `2xx` within **10 seconds** to acknowledge. The body of
your response is ignored (its first 1 KB is kept in the delivery log).

| Your response | What happens |
|---|---|
| `2xx` | delivered |
| `408`, `425`, `429`, `5xx`, timeout, connection error | retried with backoff: 30 s, 2 m, 10 m, 30 m, 1 h, 3 h, 6 h (8 attempts, ~11 h in total) |
| other `4xx` | failed, not retried |
| `3xx` | redirects are followed only to the same scheme, host and port (at most 3); anything else fails, not retried |

Deliveries are **at least once**: a retry after a timeout can repeat a
notification you already processed. De-duplicate on `X-Upkeep-Delivery`
(or the body's `delivery_id`).

### Destination rules (SSRF protection)

The URL is chosen by the user but fetched by the platform, so the worker
(`server/internal/netguard`) only connects to public destinations:

- `https` only, port `443` or `8443`, no `user:password@` in the URL;
- every address the host name resolves to must be public unicast. Loopback,
  RFC 1918, CGNAT (`100.64/10`), link-local (`169.254/16`, the cloud
  metadata service), IPv6 unique-local / link-local, multicast, reserved and
  documentation ranges, and IPv6 forms embedding an IPv4 address
  (IPv4-mapped, NAT64, 6to4, Teredo) are refused;
- the check runs on the exact IP being connected to, after resolution
  (so a DNS answer that changes between validation and delivery — DNS
  rebinding — is still caught), and again on every redirect;
- `HTTP(S)_PROXY` environment variables are ignored.

A refused destination fails the delivery permanently with a
"destination not allowed" error in the delivery log. (The email channel
applies the same address rules to its SMTP server, on the mail ports 25,
465, 587 and 2525 instead of https ports — see
[ARCHITECTURE.md § Email (SMTP) channel](ARCHITECTURE.md#email-smtp-channel).)

**Dev only:** `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS=true` on the worker (and on
the web app, for form validation) allows plain `http`, any port and private
or loopback addresses (for SMTP too), so you can point a channel at a
receiver on your own machine. It is off by default, the worker logs a warning when it is on, and
it must never be set in production.

## Body

```json
{
  "version": 1,
  "id": "798d123e-aef2-4b58-888b-b42c3e9e0496",
  "delivery_id": "4b579242-c8a0-4aa3-b735-edb445302c81",
  "kind": "alert",
  "created_at": "2026-09-27T12:34:13Z",
  "rule": { "id": "0b6f…", "name": "Critical and KEV" },
  "summary": "New finding CVE-2024-6387 in openssh on web-1 (critical, KEV)",
  "events": [
    {
      "id": 1042,
      "type": "finding.opened",
      "occurred_at": "2026-09-27T12:34:12Z",
      "url": "https://upkeep.example.com/dashboard/hosts/5c1e…/vulnerabilities?v=CVE-2024-6387",
      "host": { "id": "5c1e…", "hostname": "web-1", "label": null },
      "finding": {
        "id": "a8f2…",
        "kind": "vulnerable_package",
        "vuln_key": "CVE-2024-6387",
        "source_package": "openssh",
        "packages": ["openssh-client", "openssh-server"],
        "installed_version": "1:9.6p1-3ubuntu13",
        "fixed_version": "1:9.6p1-3ubuntu13.3",
        "fix_channel": "standard",
        "severity": "critical",
        "severity_rank": 6,
        "kev": true,
        "epss": 0.83,
        "status": "open",
        "first_seen_at": "2026-09-27T12:34:12Z"
      }
    }
  ]
}
```

| Field | Notes |
|---|---|
| `version` | Payload version, currently `1`. Additive changes (new fields, new event types, new objects on events) don't bump it; ignore what you don't know. |
| `kind` | `alert`: matches of one rule from one evaluation pass (usually one event, more when a host reports many changes at once). `digest`: a rule's matches over its digest interval. `test`: "Send test"; `rule` is `null` and `events` is empty. `report`: a scheduled estate report ([below](#report-notifications)); `rule` is `null`, `events` is empty and `report` is set. |
| `summary` | One human-readable line. |
| `events` | At most 200 per notification (larger batches are split into several). |
| `events[].url` | Present only when the worker has `SW_DASHBOARD_URL` set. |

Event types and the objects they carry:

| `type` | Objects | Notes |
|---|---|---|
| `finding.opened` | `host`, `finding` | a vulnerable package (host or container image) finding appeared |
| `finding.reopened` | `host`, `finding` | a resolved finding matched again |
| `finding.resolved` | `host`, `finding` | upgraded, removed, advisory withdrawn, kernel no longer running, or (images) no container uses the image any more; `finding.status` is `resolved` |
| `agent.stale` | `agent` | silent for more than `max(3 × push interval, 120 s)` (the dashboard's "stale") |
| `agent.recovered` | `agent` | a stale agent pushed again |

`agent` is `{ "id", "name", "last_seen_at", "hosts": [{ "id", "hostname", "label" }] }`.
Future event families (e.g. port exposure) add their own object.

`finding.kind` is `vulnerable_package` (a package installed on the host)
or `vulnerable_image` (a package in a container image that a container on
the host uses; one finding per host, image, source package and CVE).
Image findings add `image_id` (the image's content id), `image_refs` (its
repo tags on the host, or repo digests when untagged) and `containers`
(names of the containers using it), and their `url` points at the host's
Images tab. Alert rules can be limited to either kind.

`finding.severity` is the dashboard's bucket (`critical`, `high`, `medium`,
`unknown`, `low`, `negligible`); `fix_channel` is `standard`, `ubuntu-pro`
(fix only in Ubuntu Pro) or `null` (no fix yet).

## Report notifications

A report schedule (weekly or monthly, under Settings → Notification
settings) sends the whole estate's state, organised as a patch list, to its
channels; "Send now" sends one at once. The webhook gets the same envelope
and signature as an alert, with `kind: "report"` and the stored report in
`report`:

| Field | Notes |
|---|---|
| `summary` | `"{schedule name}: {summary}"`, e.g. `Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting` (`all clear` when there is nothing). The same line titles the ntfy push and the email. |
| `report.id` | The stored report. Every retry of a delivery sends the same report. |
| `report.url` | The report's dashboard page. Present only when the worker has `SW_DASHBOARD_URL` set. |
| `report.snapshot` | The full report, exactly as stored. |

```json
{
  "version": 1,
  "id": "3e0c9a4b-…",
  "delivery_id": "8d2f7c61-…",
  "kind": "report",
  "created_at": "2026-09-28T07:00:04Z",
  "rule": null,
  "summary": "Monday patch list: 1 urgent action, 2 to patch this week, 1 image to update, 1 host not reporting",
  "events": [],
  "report": {
    "id": "e5f6a7b8-…",
    "url": "https://upkeep.example.com/dashboard/reports/e5f6a7b8-…",
    "snapshot": {
      "schema_version": 1,
      "ranking_version": 1,
      "generated_at": "2026-09-28T07:00:04Z",
      "period": { "start": "2026-09-21T07:00:03Z", "end": "2026-09-28T07:00:04Z" },
      "trigger": "scheduled",
      "schedule": { "id": "6f1c2b1e-…", "name": "Monday patch list", "cadence": "weekly", "timezone": "Europe/London" },
      "estate": { "hosts": 4, "containers": 7, "images": 3 },
      "headline": {
        "patch_now": 1, "patch_this_week": 2, "when_convenient": 1, "images_to_update": 1,
        "reboots_required": 1, "no_fix_findings": 14, "total_open_findings": 42,
        "opened_since_last": 15, "resolved_since_last": 3, "stale_agents": 1
      },
      "host_actions": [
        {
          "tier": "patch_now",
          "package": "openssl",
          "binary_packages": ["libssl3", "openssl"],
          "fixed_version": "3.0.2-0ubuntu1.18",
          "fix_channel": "standard",
          "requires_pro": false,
          "kev": true,
          "worst_severity": "critical",
          "max_epss": 0.94312,
          "cves": ["CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1003"],
          "cve_count": 3,
          "hosts": [{ "id": "0b8e7f52-…", "name": "db-1" }, { "id": "1a2b3c4d-…", "name": "web-1" }, { "id": "2b3c4d5e-…", "name": "web-2" }],
          "host_count": 3,
          "oldest_open_at": "2026-09-03T14:22:10Z"
        }
      ],
      "image_actions": [
        {
          "tier": "patch_this_week",
          "image_id": "sha256:4f2a9c1d…",
          "image_refs": ["nginx:1.27", "nginx:latest"],
          "os": "linux", "arch": "arm64", "variant": "v8",
          "kev": false,
          "worst_severity": "high",
          "max_epss": 0.1234,
          "open_findings": 18,
          "fixable_findings": 11,
          "containers": ["proxy", "static-site"],
          "hosts": [{ "id": "1a2b3c4d-…", "name": "web-1" }, { "id": "2b3c4d5e-…", "name": "web-2" }],
          "oldest_open_at": "2026-08-30T02:11:47Z"
        }
      ],
      "reboots_required": [
        { "host_id": "2b3c4d5e-…", "host_name": "web-2", "packages": ["linux-image-5.15.0-122-generic"], "since": "2026-09-25T03:14:00Z" }
      ],
      "no_fix": { "findings": 14, "kev_findings": 0, "worst_severity": "high", "host_package_findings": 9, "image_findings": 5 },
      "coverage": {
        "stale_agents": [
          { "agent_id": "9c8b7a6f-…", "name": "backup-agent", "last_seen_at": "2026-09-19T22:47:12Z",
            "hosts": [{ "id": "3c4d5e6f-…", "name": "backup-1" }] }
        ],
        "hosts_without_docker": [{ "id": "3c4d5e6f-…", "name": "backup-1" }],
        "images_not_scored": []
      },
      "hosts": [
        { "id": "0b8e7f52-…", "name": "db-1", "patch_now": 1, "patch_this_week": 1, "when_convenient": 0,
          "images_to_update": 0, "reboot_required": false, "no_fix_findings": 2, "total_open_findings": 9 }
      ],
      "changes": {
        "previous_report_id": "d4e5f6a7-…",
        "previous_generated_at": "2026-09-21T07:00:03Z",
        "comparable": true,
        "metrics": {
          "patch_now": { "previous": 0, "current": 1, "delta": 1, "percent": null },
          "total_open_findings": { "previous": 30, "current": 42, "delta": 12, "percent": 40 }
        },
        "hosts_added": [
          { "id": "0b8e7f52-…", "name": "db-1",
            "contribution": { "patch_now": 1, "patch_this_week": 1, "no_fix_findings": 2, "total_open_findings": 9 } }
        ],
        "hosts_archived": []
      }
    }
  }
}
```

(Abbreviated: lists are cut to one or two entries and `changes.metrics`
to two keys; a real snapshot lists everything. The complete example is
[`web/src/lib/report-snapshot.example.json`](../web/src/lib/report-snapshot.example.json).)

The snapshot's shape is versioned by `schema_version` (breaking changes
bump it; new fields don't). Conventions:

- Lists are complete (nothing is truncated) and never `null`; optional
  values are present as `null`, never omitted. Timestamps are RFC 3339 UTC.
- `headline` holds the top-line numbers. `patch_now` / `patch_this_week` /
  `when_convenient` count **action lines** (one upgrade of one package, or
  one image to re-pull or rebuild), not CVEs: KEV → patch now;
  critical/high with a fix, or high EPSS → patch this week; the rest →
  when convenient. `opened_since_last` / `resolved_since_last` cover
  `period`.
- `host_actions` (one line per package upgrade, with the hosts it affects
  and the CVEs it closes) and `image_actions` are sorted most urgent
  first. `coverage` is always present: agents not reporting, hosts
  without Docker collection and images whose findings are unknown, so an
  empty patch list can't be mistaken for "all clear" when parts of the
  estate aren't being watched.
- `changes` compares with the schedule's previous report (`null` for the
  first one). Every headline number gets an absolute `delta`; `percent`
  only when the previous value is at least 10. When `ranking_version`
  changed between the two reports, `comparable` is `false` and `metrics`
  only has the numbers that don't depend on the ranking
  (`total_open_findings`, `opened_since_last`, `resolved_since_last`,
  `stale_agents`). `hosts_added` / `hosts_archived` attribute changes to
  hosts that joined or left the estate.
- Hosts are named by their dashboard label, else their hostname. The
  snapshot has no URLs; `report.url` is built when the delivery is sent.

## Verifying the signature

Each channel has a signing secret (`whsec_…`), generated by the server and
shown once when the channel is created or its secret rotated.

```
signed_payload = X-Upkeep-Timestamp + "." + raw request body
signature      = "v1=" + hex( HMAC-SHA256(key = secret, message = signed_payload) )
```

1. Read the **raw** body bytes; don't re-serialize parsed JSON.
2. Compute the signature and compare it to `X-Upkeep-Signature` in constant
   time. (The header may carry several comma-separated values in future;
   accept if any matches.)
3. Reject timestamps more than 5 minutes from your clock, to stop replays.

Python:

```python
import hashlib, hmac, time

def verify(secret: str, headers, body: bytes, tolerance=300) -> bool:
    ts = headers["X-Upkeep-Timestamp"]
    if abs(time.time() - int(ts)) > tolerance:
        return False
    want = "v1=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(want, s.strip()) for s in headers["X-Upkeep-Signature"].split(","))
```

Node.js:

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verify(secret, headers, rawBody, toleranceSec = 300) {
  const ts = headers["x-upkeep-timestamp"];
  if (Math.abs(Date.now() / 1000 - Number(ts)) > toleranceSec) return false;
  const want = Buffer.from(
    "v1=" + createHmac("sha256", secret).update(`${ts}.`).update(rawBody).digest("hex"),
  );
  return headers["x-upkeep-signature"].split(",").some((s) => {
    const got = Buffer.from(s.trim());
    return got.length === want.length && timingSafeEqual(got, want);
  });
}
```

Go: `webhook.Verify` in `server/internal/notify/webhook` is the reference
implementation.

Shell (for a quick check):

```sh
printf '%s.%s' "$TIMESTAMP" "$BODY" | openssl dgst -sha256 -hmac "$SECRET"
```

To rotate a secret without downtime, accept both the old and the new
secret for a short while after rotating.
