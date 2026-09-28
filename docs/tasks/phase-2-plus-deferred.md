# Phase 2+ (explicitly deferred, don't start early)
- [ ] External port-exposure scanner (deferred 2026-09-27, [Port
      exposure](../decisions/port-exposure.md)): probe only an enrolled agent's own
      `snapshots.source_ip`, rate-limited, never an arbitrary target;
      skip private / CGNAT / loopback source IPs ("can't verify"); remote
      (SSH) hosts ineligible (Q5). Its vantage point is the platform
      box, not the internet, which self-hosters' private networks and
      allowlists make misleading.
- [ ] RHEL/Alpine package collectors (agent currently Debian/Ubuntu-only
      by design).
- [ ] SMS notifications.
- [ ] Discord notifier (webhook URL as a secret field, embed formatting).
- [ ] Slack notifier (incoming-webhook URL; Block Kit formatting).
- [ ] Billing/Stripe (see [Billing deferred](../decisions/billing-deferred.md) — deferred until real users).
- [ ] Multi-tenant orgs/teams (see [Single-user tenancy](../decisions/single-user-tenancy.md) — deferred until demand).
- [ ] Cache layer + revalidation webhook for dashboard reads (only
      needed if a specific page is actually slow — see [Direct Postgres reads](../decisions/direct-postgres-reads.md)).
