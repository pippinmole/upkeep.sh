# Phase 1 remainder — packages & vulnerabilities UI (P1c)
Design: [DOMAIN_MODEL.md §3](../DOMAIN_MODEL.md#3-packages-in-the-dashboard).
Direct Postgres reads from Server Components, filters in URL search
params, no new Go endpoints.
- [x] Host detail shell `/dashboard/hosts/[hostId]` (header: OS, last
      seen, reboot pill, collector-health alerts; link tabs).
- [x] Host header vuln/KEV pills (open count, top severity, KEV count)
      and running kernel (`snapshots.kernel_release`, "unknown" shown
      explicitly); same pills on the host list rows.
- [x] Packages tab: searchable/filterable per-host inventory,
      installed-since, `?at=<date>` point-in-time view.
- [x] Packages tab P1b columns: status (open findings via
      `host_package_vuln_status`; non-running kernels labelled info), top
      severity/KEV, "fixed in" (`max_fixed_version`); vulnerability filter,
      most-urgent-first default sort; `?pkg=` row sheet with the package's
      CVEs. Under `?at=` the counts are that version's matches against
      today's advisories.
- [x] Vulnerabilities tab `/dashboard/hosts/[hostId]/vulnerabilities`:
      open findings most urgent first, open/resolved toggle, severity/KEV/
      fix filters, `?v=` detail sheet (CVE + advisories), running-kernel
      panel from `host_kernel_packages`.
- [x] History tab: installed/removed/"changed" per range boundary, paired
      on read by (ecosystem, name, arch).
- [x] History tab: upgraded vs downgraded (deb, via a TS port of dpkg
      ordering in `web/src/lib/debversion.ts`, checked against the Go
      package's 806 dpkg vectors) and "fixed N / introduced N" per change
      (set difference of `software_vulnerabilities`, today's advisory
      data), computed on read.
- [ ] Move the FilterBar tables (host packages / vulnerabilities / history,
      fleet packages / vulnerabilities) to `DataTable` in server mode
      (`web/src/components/data-table/`, `tableStateFromParams` +
      `useServerTable`); the SQL side keeps its allowlisted sort keys and
      bound params (DOMAIN_MODEL Q11).
- [ ] `host_software_changes` derived table written by ingest (pairing +
      direction once in Go) — only if the on-read History tab gets slow.
- [x] Fleet `/dashboard/vulnerabilities` (open / "resolved everywhere",
      filters, sorts) + `/dashboard/vulnerabilities/[vulnKey]` (CVE
      facts, affected hosts, affected versions on your hosts, previously
      affected = resolved findings, per-release fixes, advisories).
- [ ] "Previously affected" from inventory ranges (hosts that had a
      vulnerable version before findings existed); today it is resolved
      findings only.
- [ ] Automated test for `web/src/lib/debversion.ts` against
      `server/internal/debversion/testdata/dpkg_compare_vectors.txt`
      (checked by hand; web/ has no test runner yet).
- [x] Fleet `/dashboard/packages` + `/dashboard/packages/[name]` ("which
      hosts have package X, at which versions", previously installed).
- [x] Overview page: hosts (stale), open findings by severity, KEV,
      reboot pending, fix available / Pro-only / no fix, top 5 vulns.
- [x] shadcn components: `select`, `pagination` (host tabs are link tabs,
      so `tabs` wasn't needed).
- [ ] Fleet vulnerability list aggregates all of a user's findings
      (open + resolved) per request (per host via
      `findings_host_status_idx`, ~8 ms for 450 rows). If resolved history
      grows large, split the open and resolved paths or keep a per-user
      summary.
- [ ] Index `host_software (software_id) WHERE removed_at IS NOT NULL`
      for "previously installed/affected" fleet queries.
- [ ] 24 pre-existing files fail `oxfmt --check` (ui/*, nav-*, providers).
