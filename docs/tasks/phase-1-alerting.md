# Phase 1 remainder — alerting
Port exposure moved to host-side analysis in [Phase 1.6](phase-1-6-docker-exposure.md); the
external scanner is deferred to Phase 2+ ([Port exposure](../decisions/port-exposure.md)).
- [x] Alert rule evaluation worker + dispatch (migration 0009,
      `internal/alerting`, `jobs/alerting.go`): rules on finding opened /
      reopened / resolved (min severity, KEV-only, host scope) and agent
      stale / recovered (`agent_health`, the dashboard's stale rule);
      dedup per (rule, event type, subject) within a window; digest mode;
      delivery with River retries/backoff and a per-attempt log.
- [x] Generalized notifier (`internal/notify`: `Notifier` interface,
      declared field schema, registry) with the **webhook** type:
      HMAC-SHA256-signed JSON POST ([WEBHOOKS.md](../WEBHOOKS.md)), SSRF guard
      `internal/netguard` (https, ports 443/8443, public IPs checked at dial
      time, same-origin redirects; dev escape hatch
      `SW_NOTIFY_ALLOW_PRIVATE_NETWORKS`; a separate SMTP policy for the
      email channel, see below).
- [x] Dashboard: rules and delivery log with attempts under
      `/dashboard/alerts`; channels (form rendered from the type's schema,
      secret shown once + rotate, "Send test") under
      `/dashboard/settings/notifications`; all on `DataTable`, server
      actions scoped by `user_id`.
- [x] **ntfy** notifier (`internal/notify/ntfy`): JSON publish to ntfy.sh
      or a self-hosted server (topic validated against ntfy's charset,
      optional Bearer access token, automatic or fixed priority);
      human-readable title/body, priority from severity/KEV (KEV or
      critical → urgent, resolved/recovered → low, digests capped at high),
      emoji tags, `click` to the dashboard link. Through `netguard`, so a
      self-hosted server must be public https on 443/8443
      ([ARCHITECTURE.md § ntfy channel](../ARCHITECTURE.md#ntfy-channel)).
- [x] **Email (SMTP)** notifier (`internal/notify/email`): plain-text mail
      through the user's own SMTP server. **SMTP settings are per channel**
      (host, port, security, username/password, from, to), entered in the
      channel form like webhook and ntfy; there is no platform-wide SMTP
      config ([Email notifier](../decisions/email-notifier-smtp.md)). Security STARTTLS (default, required when
      chosen), implicit TLS or none; certificates always verified.
      **"Allow insecure authentication"** (default off): credentials are
      never sent over a connection without TLS unless it is on. Subjects
      and bodies share ntfy's rendering (`internal/notify/render`); headers
      are CR/LF-safe, subjects RFC 2047 encoded. 4xx/connection errors are
      retried, 5xx/auth/TLS failures fail at once. `netguard` gained an
      **SMTP policy** (ports 25, 465, 587, 2525; same public-address
      checks at dial time and dev escape hatch; the https rules are
      unchanged)
      ([ARCHITECTURE.md § Email (SMTP) channel](../ARCHITECTURE.md#email-smtp-channel)).
- MVP notification channels are **webhook + ntfy + email (SMTP)**;
  Discord and Slack are deferred to Phase 2+ (a webhook can already feed
  most chat tools).
- [ ] Encrypt channel secrets at rest (`notification_channels.secrets` is
      plaintext today; the worker needs the webhook secret to sign, so it
      would need a key shared by web + worker, e.g. `SW_SECRETS_KEY`).
- [x] Archived hosts don't alert: no finding events for them, and they're
      left out of agent events' `host_ids` / payload (`store/alerting.go`).
- [ ] Alerting: per-user rate limit / circuit breaker for a channel that
      keeps failing (today each delivery retries independently for ~11 h).
- [ ] Exposure events: see [Phase 1.6](phase-1-6-docker-exposure.md) (a new event type + `Event` object,
      no dispatch changes).
