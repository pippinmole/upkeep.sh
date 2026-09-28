# Phase 1.7 — scheduled estate reports
Decided 2026-09-28 ([Scheduled reports](../decisions/scheduled-reports.md) and [Report email
HTML](../decisions/report-email-html.md)). Not started. A weekly or monthly report of the whole estate,
organised as a patch list, sent to existing notification channels. It's
separate from alert rules: reports describe state (everything open now),
digests describe events. Order: schema, then snapshot builder, then
delivery, then the email template, then the dashboard.
- [ ] Migration: `report_schedules` (user, name, enabled, cadence
      `weekly` | `monthly`, weekday or day of month, hour, IANA timezone,
      `next_run_at`, created/updated), `report_schedule_channels`
      (composite same-owner FKs like `alert_rule_channels`), `reports`
      (schedule, user, generated at, period covered, ranking version,
      snapshot `jsonb`, previous report id). Whole estate only for now:
      no host scope column yet. Ownership: Next.js writes schedules and
      their channels; the Go worker writes `reports` and
      `report_schedules.next_run_at`. Add both to ARCHITECTURE.md "Who
      owns what".
- [ ] Snapshot builder (Go, `internal/reports`), one read transaction
      per report. It includes:
      - **Estate**: host, container and image counts.
      - **Host-package actions**: open `vulnerable_package` findings
        grouped by (package, fixed version), with the hosts affected,
        the CVEs closed and the oldest open date. When several CVEs
        need different versions, the fix is the highest version.
      - **Image actions**: `vulnerable_image` findings grouped by image,
        with containers/hosts using it and fixable counts. The action is
        to re-pull or rebuild.
      - **Reboots required**.
      - **No fix available yet**: counts plus the worst severity.
      - **Coverage gaps**: stale agents with last seen time, hosts
        without Docker collection, images not scored.
      - **Per-host counts** and the ranking version.

      Tiers use the existing `severity` ranking: KEV → patch now;
      critical/high with a fix or high EPSS → patch this week; the
      rest → when convenient. Archived hosts are excluded. Unit-test the
      grouping against fixed data.
- [ ] Week-on-week comparison with the previous report of the same
      schedule: absolute changes for every headline number (urgent,
      patch this week, images to update, total open, opened/resolved
      since last report). A percentage only when the previous value is
      ≥ 10. No comparison when the ranking version differs. Attribute
      changes to hosts added or archived since the previous report.
- [ ] Worker jobs: `report_due` (periodic, 1m; advisory-locked; builds,
      stores, advances `next_run_at` in the schedule's timezone,
      including DST changes; inserts a `report` notification + one
      delivery per channel + `alert_deliver` jobs in the same
      transaction). A missed run (worker down) runs once when it comes
      back, not once per missed period. Integration test in
      `jobs/` with a fake channel, like `alerting_integration_test.go`.
- [ ] `report` notification kind per channel:
      - **Webhook**: the full snapshot JSON, documented in WEBHOOKS.md
        with an example.
      - **ntfy**: a summary title ("3 urgent actions, 2 hosts not
        reporting"), headline numbers in the body and `click` to the
        report page. Priority 3; 4 when there are KEV actions.
      - **Email**: HTML + text from the render endpoint (next item).
- [ ] React Email: add `react-email` to `web/` at an **exact** version
      (no `^`), the latest on npm at install time (6.11.0 on
      2026-09-28; `@react-email/components` is deprecated). Report
      template in `web/src/emails/`. Internal route (e.g.
      `POST /api/internal/render/report`), authenticated with a shared
      secret (`SW_INTERNAL_RENDER_SECRET` in both web and worker;
      constant-time compare) and refused on the public host; the worker
      reaches it at `SW_WEB_INTERNAL_URL`. Returns `{subject, html,
      text}`. The email channel gains an HTML part
      (`multipart/alternative`) for `report` notifications only; alert
      emails stay plain text. A render failure (web down, 5xx) is
      retryable. Keep the HTML simple enough for Gmail/Outlook (React
      Email's components handle that) and under Gmail's ~102 KB clip
      limit, with long lists cut to "…and N more, see the full report".
      Preview the template with the `email` dev CLI.
- [ ] Dashboard, **Settings → Notification settings**: a Reports
      section listing schedules (name, cadence, channels, next run, last
      run). Create/edit dialog: name, weekly/monthly, day, hour,
      timezone (defaults to the browser's), channels. A "Send now" button
      (a real run: web inserts a River job like "Send test"; the report
      is stored, delivered and counted as the previous report for next
      time). No "Preview" (decided 2026-09-28, for simplicity): the
      builder is Go, so a preview would need a preview job or a worker
      HTTP endpoint. To see a report, send it now and open it from the
      past reports list.
- [ ] Dashboard: past reports, meaning a list per schedule and a report
      page showing a stored snapshot (the link target of emails and
      ntfy). Deliveries show in the existing delivery log.
- [ ] Retention: prune `reports` older than a year (keep the latest
      per schedule regardless), in `alert_prune`.
- [ ] Docs: ARCHITECTURE.md "Reports" section (flow, ownership rows,
      the web ↔ worker render dependency), README feature list, deploy
      env vars (`SW_WEB_INTERNAL_URL`, `SW_INTERNAL_RENDER_SECRET`) in
      the compose files.
