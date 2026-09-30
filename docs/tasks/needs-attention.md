# Overview — Needs attention

Design and candidate list: [NEEDS_ATTENTION.md](../NEEDS_ATTENTION.md).

- [x] Provider registry (`web/src/lib/attention/`): each item kind is a
      small aggregate query plus a pure mapper, ranked by severity then
      registry order, capped at 6 on the Overview with a "View all" page
      (`/dashboard/attention`). Ownership in one place (`owner.ts`).
      Existing 8 kinds moved onto it; new: host sockets exposed through the
      host mount, critical vulnerabilities with a fix available, OS past end
      of life (and within 90 days), failing collectors, duplicate hosts to
      review, no enabled notification channel.
- [ ] Images on an end-of-life base OS (image SBOM distro vs
      `distro_releases.eol_date`).
- [ ] Remote (SSH) collection failing: enabled ssh `agent_hosts` with
      `last_error`.
- [ ] Outdated agent versions, once the server knows the latest released
      version (release feed or a build-time constant).
- [ ] Vulnerability feeds stale or failing (`feed_sync_state`), shown to
      admins only (docs/MEMBERS.md roles).
- [ ] Credential rotation requested but not picked up after a few push
      intervals.
- [ ] Unattended upgrades disabled, once it's stored as a host fact.
- [ ] Snooze / dismiss an item (per kind, per workspace), if users ask for
      it: today an item goes away only when its cause does.
