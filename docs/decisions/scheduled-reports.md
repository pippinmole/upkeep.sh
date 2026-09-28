# Scheduled reports: a separate feature, about state rather than events

Considered (2026-09-28): some users don't want an alert every time
something changes. They want "every week, a report of my whole estate:
what do I need to patch". Options: a new mode on alert rules (a longer
digest), or a separate feature.

**Decided: a separate feature, scheduled reports.** A digest batches
**events** (opened / reopened / resolved within the interval), so it
can't say "you still have 40 unpatched CVEs". A finding that was open
last week and is still open produces no event, so a quiet week gives an
empty digest. A report describes **state**: everything open at the
moment it runs, ranked into actions, plus how that changed since the
previous report. Alert rules filter events; report schedules run on a
calendar over state. Folding reports into rules would give rules a mode
where most of their fields (event types, dedup window) don't apply.

- **Configured under Settings → Notification settings**, next to the
  channels (user decision). "Who to" means channels: reports are sent
  to existing notification channels (email, webhook, ntfy), so there's
  no second list of recipients or SMTP settings (see
  [Email notifier](email-notifier-smtp.md)). "How often" means a schedule: weekly (weekday and hour) or
  monthly (day and hour), in a timezone the user picks.
- **Whole estate for now** (user decision): every non-archived host and
  its images. Scoping (like `alert_rules.host_ids`) can come later.
- **Organised by action, not by CVE.** One line per upgrade
  (package → fixed version), with the hosts it affects and the CVEs it
  closes. Sections: patch now (KEV), patch this week (critical/high with
  a fix, or high EPSS), images to update (re-pull or rebuild), reboots
  needed, no fix available yet (tracked, nothing to do), coverage gaps
  (agents not reporting, hosts without Docker collection). Ranking uses
  the existing `severity` rules (KEV first, then EPSS, CVSS only breaks
  ties). Host packages and images stay separate, as on the Overview
  page: they are fixed differently. The coverage section is always
  present, because a report that says "all clear" when agents have
  stopped reporting gives false reassurance.
- **Every generated report is stored** as a JSON snapshot (a `reports`
  row per run). Week-on-week changes ("13 more urgent CVEs than last
  week, +12%") compare against the previous stored report of the same
  schedule, so storing each run is what makes them possible. Storing
  also means a retried delivery sends exactly the same content, and the
  dashboard can list past reports.
  - Absolute changes are always shown. Percentages only appear when the
    previous value is large enough to be meaningful (at least 10):
    0 → 3 is not "+∞%" and 1 → 2 is not "+100%".
  - Each snapshot records the ranking version it used. When the
    definitions change between two reports (what counts as "urgent"),
    no change is shown for the affected numbers, rather than comparing
    different things.
  - Snapshots keep per-host counts, so a change can be attributed ("9 of
    the 13 are on web-4, added this week"). Otherwise, adding a host
    looks like the estate got worse.
- **Generated and delivered by the Go worker**, like alerts: a River
  job finds due schedules, builds the snapshot in one read transaction,
  stores it and queues one delivery per channel through the existing
  `notifications` / `notification_deliveries` / `alert_deliver` path
  (retries, backoff and the delivery log unchanged). A new notification
  kind, `report`, is rendered per channel: the whole report by email,
  the snapshot JSON by webhook (WEBHOOKS.md), a summary line and a
  dashboard link on ntfy (its 4 KB limit).
