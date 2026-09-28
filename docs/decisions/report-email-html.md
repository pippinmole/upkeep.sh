# Report email HTML: React Email, rendered by Next.js

Decided (2026-09-28, user decisions): report emails are HTML (with a
plain-text part), built with [React Email](https://react.email/).

- **Package: `react-email`, pinned to an exact version** (no `^`),
  the latest when it's installed. As of 2026-09-28 that's `6.11.0`.
  `@react-email/components` is deprecated on npm; the components now
  ship in `react-email` itself. Check the registry again at install
  time rather than trusting this version (see [Version policy](version-policy.md)).
- **Rendered by an internal endpoint in Next.js, sent by the Go
  worker.** React Email renders JSX in JavaScript, but delivery (SMTP,
  retries, delivery log) lives in the worker. The worker posts the
  stored snapshot to an internal route in `web/` that returns
  `{subject, html, text}` and is authenticated with a shared secret. It
  must not be reachable through the public site. The worker then sends
  as today. The templates live in `web/`, next to the dashboard code
  that already knows how to show findings. Cost: sending a report email
  depends on `web` being up. A failed render is treated like a
  retryable send failure (same backoff), never as a permanent one.
  Rejected: a Bun render script inside the worker image (a second
  runtime to ship) and generating reports in Next.js (splits
  scheduling and delivery across two runtimes).
- **Reports only.** Alert emails (single events and digests) stay
  plain text rendered in Go (`internal/notify/render`). Revisit once
  the render path has proven itself on reports.
