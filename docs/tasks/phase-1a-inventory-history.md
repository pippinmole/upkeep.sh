# Phase 1 remainder — package inventory history (P1a)
Design: [DOMAIN_MODEL.md §2.2](../DOMAIN_MODEL.md#22-storage-model-for-inventory-history).
The agent already sends the full dpkg inventory every push; what's missing
is a history model that doesn't copy ~1,500 rows per snapshot.
- [x] Agent: send `source` / `source_version` per package from dpkg's
      `Source:` field (`Source: foo` and `Source: foo (1.2-3)` forms;
      absent → same as binary). Additive, stays `schema_version: 1`.
- [x] Agent: fix the installed-state check in `parseDpkgStatus` —
      `strings.Contains(status, "installed")` also matches
      `half-installed` / `not-installed`; test the third word of
      `Status:` instead.
- [x] Agent: also count `triggers-pending` / `triggers-awaited` as
      installed (files on disk, only a trigger outstanding), so a push
      landing mid-`apt` doesn't record false remove/re-add history.
- [x] Migration `0003_inventory_history`: `software_versions`
      (fleet-wide interned, key `(ecosystem, distro, release, name,
      version, arch)`) + `host_software` validity ranges, per-(host,
      ecosystem) `host_inventory_state` (set hash + last confirmed; replaces
      the single `hosts.current_package_set_hash`),
      `snapshots.package_set_hashes` + `snapshots.collector_status`,
      `hosts(user_id)` index.
- [x] Ingest: per-ecosystem diff against open ranges in the snapshot
      transaction, host row locked; skipped entirely when the set hash is
      unchanged; never closes ranges for an ecosystem whose collector isn't
      `ok` or when `packages` is null/missing (rules for old agents in
      PROTOCOL.md). `server/internal/inventory` + `ingest/inventory.go`.
- [x] Backfill `host_software` by replaying existing `snapshot_packages`
      in order (set-based SQL in migration 0003, idempotent).
- [x] Stop writing `snapshot_packages` and drop it (migration
      `0004_drop_snapshot_packages`; DOMAIN_MODEL.md Q6 resolved: retire).
- [x] Fix `store.InsertSnapshot` hardcoding `schema_version = 1` instead
      of using the payload's value.
- [ ] Agent-clock robustness: range boundaries use `collected_at`
      (clamped to server time). A host clock that jumps *backwards* makes
      pushes look stale (stored, not diffed) until it catches up; consider
      falling back to `received_at` when that happens.
