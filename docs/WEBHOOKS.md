# Webhooks

A **webhook** notification channel receives an HTTPS `POST` of a JSON
document for every notification a rule sends to it (and for "Send test").
Channels are configured under **Dashboard → Settings → Notification
settings** and the rules that send to them under **Dashboard → Alerts**
(which also holds the delivery log); the pipeline behind them is described in
[ARCHITECTURE.md § Alerting](ARCHITECTURE.md#alerting).

## Request

```
POST /your/path HTTP/1.1
Content-Type: application/json
User-Agent: upkeep.sh-webhook/1
X-Upkeep-Kind: alert                       # alert | digest | test
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
| `kind` | `alert`: matches of one rule from one evaluation pass (usually one event, more when a host reports many changes at once). `digest`: a rule's matches over its digest interval. `test`: "Send test"; `rule` is `null` and `events` is empty. |
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
