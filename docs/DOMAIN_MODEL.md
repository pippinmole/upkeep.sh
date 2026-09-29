# Domain model, package inventory and vulnerability matching

Design doc, 2026-09-26. Status: **proposal**, partly implemented: P1a
(inventory history, §2.2) is built, and the differences are listed under
"As implemented" in §2.2. The rest has not been migrated or coded.
Where this doc and the code disagree, the
code is the truth about *today*, and this doc is the plan. Open questions
for the user are collected in [section 6](#6-open-questions); anything
marked **(judgment call)** in the body is also listed there.

It covers three connected changes:

1. **Vulnerability reporting.** The agent reports the full package inventory.
   The server keeps that inventory's history and joins it against advisory
   data.
2. **Packages in the dashboard**: per-host packages, change history, and
   fleet-wide package and CVE views.
3. **Domain model**: split *agent* from *host*, add OS families
   (Linux, Windows, macOS), and pick a schema shape for per-OS data.

Contents:

- [1. Current state (verified in code)](#1-current-state-verified-in-code)
- [2. Package inventory and vulnerability matching](#2-package-inventory-and-vulnerability-matching)
- [3. Packages in the dashboard](#3-packages-in-the-dashboard)
- [4. Domain model: agents, hosts, OS families](#4-domain-model-agents-hosts-os-families)
- [5. Support matrix](#5-support-matrix)
- [6. Open questions](#6-open-questions)
- [7. Suggested sequencing](#7-suggested-sequencing)

---

## 1. Current state (verified in code)

### 1.1 What the agent sends

The agent **already sends the full installed package inventory**, not only
vulnerable packages. No agent change is needed to get "all packages", but
the source-package fields described below still need adding.

- `agent/internal/collector/packages.go` parses `/host/var/lib/dpkg/status`
  and returns every package whose `Status:` contains `installed`, as
  `{name, version, arch}`.
- `agent/cmd/agent/main.go` `collectSnapshot()` builds one `Snapshot` per
  push. It includes OS release (`osrelease.go`: `ID`, `VERSION_ID`,
  `VERSION_CODENAME`), listening TCP/TCP6 sockets with pid and process name
  (`ports.go`, native `/proc`), the reboot-required flag and packages
  (`reboot.go`), and best-effort public IPv4/IPv6 (`publicip.go`, via
  ipify). The push interval comes from `SW_INTERVAL`: 15m by default, 30s in
  the dev test agents.
- The payload shape is `agent/internal/collector/types.go` (agent side) and
  `server/internal/ingest/payload.go` (server side), `schema_version: 1`.

The "Phase 1 remainder" plan ([tasks/phase-1b-vuln-pipeline.md](tasks/phase-1b-vuln-pipeline.md)) was already server-side matching
("OSV sync worker … into `vulnerabilities`", then match). The agent never
had to decide what counts as vulnerable. What the plan did not have was:

- any **history model** for packages beyond "copy every row every push"
- source-package handling
- a working shape for the `vulnerabilities` table (see gap 3 below)

### 1.2 How it is stored today

*(Historical: this describes the schema before P1a. Package history now
lives in `host_software` ranges (§2.2), and `snapshot_packages` was
dropped in migration `0004_drop_snapshot_packages`, see Q6.)*

- `server/internal/ingest/handler.go` `Snapshot()` authenticated the push,
  then called `store.InsertSnapshot` (`server/internal/store/snapshots.go`).
  That inserted one `snapshots` row, then `COPY`d **every package** into
  `snapshot_packages (snapshot_id, name, version, arch)` and every socket
  into `listening_sockets`. After the insert there was a
  `TODO(phase 1)` and nothing else.
- Volume: a typical Debian/Ubuntu server has 600 to 2,000 packages. At a 15m
  interval that was roughly 60k to 190k `snapshot_packages` rows per host per
  day. At the 30s dev interval it was about 30x that. Almost all of those rows
  repeated the previous snapshot.

### 1.3 Identity and topology today: agent == host

*(Historical: this describes the model before P1.5. Migration
`0008_agent_host_split` split agents from hosts; see §4.3 and §4.7 "As
implemented".)*

- `POST /v1/enroll` (`handler.go` `Enroll()`) consumes an
  `enrollment_tokens` row, then **creates a `hosts` row**
  (`store.CreateHost`) and stores the secret hash in
  `agent_credentials (host_id PK)`. The `agent_id` it returns **is the
  `hosts.id`**.
- `POST /v1/snapshots` reads `X-Agent-ID`, looks up
  `agent_credentials.host_id` and writes `snapshots.host_id` from it. There is
  no `agents` table. "Agent" and "host" are the same row.
- In the dashboard, `web/src/app/dashboard/agents/page.tsx` ("Agents") lists
  `hosts` through `getHostsForUser` (`web/src/lib/queries.ts`). The
  "Register agent" dialog issues an enrollment token. The UI uses the two
  words for the same thing.
- The agent only runs on Linux, in Docker, with `pid: host`,
  `network_mode: host` and `/:/host:ro` (`agent/docker-compose.example.yml`).
  It always collects the machine it runs on. There is no remote collection
  and no OS family field. `snapshots.os_id` is free text from
  `/etc/os-release`.
- The hostname is sent once, at enrollment (`os.Hostname()` in
  `agent/cmd/agent/enroll.go`). It is never refreshed.

### 1.4 Gaps and bugs found while reading (relevant to this design)

1. **The dpkg parser drops the `Source:` field.** Debian and Ubuntu advisories
   are keyed by *source* package (`openssl`), but hosts install *binary*
   packages (`libssl3`, `openssl`). Without `Source:`, `libssl3` cannot be
   matched. The source version can also differ from the binary version
   (binNMUs, `Source: foo (1.2-3)`). Fix: an additive payload field.
2. **The `installed` check is too loose.** `strings.Contains(status, "installed")`
   also matches `half-installed` and `not-installed`, for example
   `purge ok not-installed`. It should test that the third word of `Status:`
   is `installed`. This is a small fix, and the first dpkg parser test should
   cover it.
   (Done. The check also accepts `triggers-pending` and `triggers-awaited`,
   whose files are fully on disk; see PROTOCOL.md.)
3. **The `vulnerabilities` table can't hold what it describes.** It has
   `id text PRIMARY KEY -- e.g. "CVE-2024-1234"`, but each row is also
   per `package_name` and `distro_release`. One CVE affects many (package,
   release) pairs, so the primary key allows only one of them. The table
   needs replacing, not just filling (see §2.4).
4. **The schema version is hardcoded on insert.** `store.InsertSnapshot`
   writes `schema_version = 1` as a literal instead of the payload's
   value. This is harmless today and wrong once v2 exists.
5. **Failure is all or nothing.** If the dpkg collector fails,
   `collectSnapshot` returns early and nothing is pushed. With history
   ranges (§2.2) that is safe, since there is no false "everything removed".
   With more collectors it is too coarse; see per-collector status in §4.5.
6. **Windows and macOS are listed as explicit non-goals** in `README.md` and
   [`docs/tasks/non-goals.md`](tasks/non-goals.md). Section 4 of this doc assumes they are coming. That
   change of product scope needs an explicit decision (open question Q1).

---

## 2. Package inventory and vulnerability matching

### 2.1 Principle

- The agent reports **facts only**: every installed package with
  binary name, version, arch, source name and source version. It never
  decides what is vulnerable. This is already the architecture, and it keeps
  the agent small and auditable.
- The server stores the inventory **as history**: which package versions
  were on which host, and when.
- The server keeps **its own copy of advisory data** and joins the two. New
  advisories apply to current *and* past inventories without the agent
  resending anything.

### 2.2 Storage model for inventory history

Four options were considered:

| Option | Rows written per push when nothing changed | Current inventory query | "What changed / as of date T" | Notes |
|---|---|---|---|---|
| A. Full copy per snapshot (today) | ~1,500 | easy | diff two snapshots | Most storage by far; needs pruning, and pruning destroys history |
| B. Change events only | 0 | replay events (or keep a separate "current" table) | natural | Two sources of truth; replay needed for "as of T" |
| C. Content-addressed package sets (hash of sorted list → set rows) | 0 | join through set | diff two sets | Dedups identical hosts well, but every single upgrade writes a whole new ~1,500-row set; "when did X appear" needs set diffs |
| **D. Validity ranges per (host, package version)** | **0** | `WHERE removed_at IS NULL` | range predicates | One table gives current state, history, and point-in-time views |

**Recommendation: D, validity ranges, plus two cheap additions:**

1. **Intern package versions fleet-wide.** A `software_versions` row is one
   distinct `(ecosystem, distro, release, name, version, arch)`, plus source
   name and version, and it never changes. Hosts reference it by id. Fifty
   hosts on the same Ubuntu release share most rows. More importantly,
   **vulnerability evaluation happens once per distinct version, not once
   per host** (§2.5).
2. **Short-circuit with a set hash.** The server computes a hash of the
   sorted `(name, arch, version, source, source_version)` list and stores it
   on the snapshot. If it equals the host's previous hash, ingest skips the
   diff entirely. This is the one piece of option C worth keeping, and it
   makes the common case (nothing changed) nearly free.

Ingest algorithm, in Go, in the ingest transaction or a job right after it:

```
if snapshot.package_set_hash == host.current_package_set_hash: done
load open rows:  host_software WHERE host_id = $1 AND removed_at IS NULL
intern reported versions (INSERT ... ON CONFLICT DO NOTHING, then SELECT ids)
added   = reported − open   → INSERT host_software (first_seen_at = collected_at, first_seen_snapshot_id)
removed = open − reported   → UPDATE host_software SET removed_at = collected_at, removed_snapshot_id
host.current_package_set_hash = snapshot.package_set_hash
enqueue evaluate(software_id) for any newly interned versions (§2.6)
```

Details:

- **An upgrade is a close plus an open.** `openssl 3.0.2-0ubuntu1.15`
  closes and `3.0.2-0ubuntu1.16` opens in the same snapshot. The History UI
  pairs these into "upgraded" by `(host, name, arch, snapshot)` (§3.4).
- **Unchanged rows don't carry `last_seen_at`.** Updating 1,500 rows per push
  is the write amplification we are trying to avoid. "Last confirmed" is a
  host-level fact instead: `hosts.inventory_confirmed_at`, or per collector
  (§4.5). An open range means "still installed as of the last successful
  inventory".
- **Missing data is never a removal.** If a push has no package section,
  or the packages collector reports an error, the diff is skipped. Today the
  agent never sends a partial payload, but multi-collector payloads will
  (§4.5).
- **Reinstalling a version later opens a new range.** The same software id
  can have several non-overlapping ranges on one host.
- **Point in time**: "the inventory at T" is
  `first_seen_at <= T AND (removed_at IS NULL OR removed_at > T)`.
- **Out-of-order pushes**: ingest uses `collected_at` as the range boundary
  but applies snapshots in `received_at` order. A snapshot collected before
  the host's newest applied inventory is stored but not diffed. With one
  agent per host and a sequential push loop, this is rare.
- **`snapshot_packages` is retired.** Backfill `host_software` from the
  existing `snapshot_packages` history by replaying snapshots in order, then
  stop writing it and drop it in a later migration. No raw per-snapshot
  package rows are kept (Q6, resolved).

**As implemented (P1a, migration `0003_inventory_history`)**, where it
differs from the sketch above:

- **Per-ecosystem hashes, not one per host.** Package sources succeed or
  fail independently (PROTOCOL.md `collectors`), so a single host-level
  hash can't say which part of the inventory it describes. Instead of
  `hosts.current_package_set_hash` there is
  `host_inventory_state (host_id, ecosystem, package_set_hash,
  confirmed_at, confirmed_snapshot_id, changed_at)`, which also provides
  the per-source "last confirmed" time mentioned above.
  `snapshots.package_set_hashes jsonb` is `{"deb": "<sha256>"}` for the
  ecosystems that were authoritative in that push.
- **Hash** = SHA-256 over a versioned, NUL-separated encoding of
  `(ecosystem, distro, release)` and the sorted, de-duplicated
  `(name, version, arch, source, source_version, source_inferred)` items
  (`server/internal/inventory`).
- **Source is not part of the interned key.** `software_versions` is
  unique on `(ecosystem, distro, release, name, version, arch)`. Older
  agents (and the backfill) send no source, so it is inferred as the
  binary name/version with `source_inferred = true`; the first real
  source reported for that version replaces it and resets the matcher
  columns. Keying on source would close and reopen every range the day an
  agent is upgraded.
- **Distro-scoped ecosystems** (`deb` today) take `distro`/`release` from
  `os.id`/`os.codename` and are only diffed when the OS is known (the `os`
  collector is ok). Other ecosystems use `''`.
- **Ordering**: the host row is locked (`FOR NO KEY UPDATE`) at the start
  of the snapshot transaction. A push whose boundary is not strictly newer
  than `confirmed_at` for that ecosystem is stored but not diffed. The
  boundary is `collected_at` clamped to the server's clock.
- **Backfill** is set-based SQL in the migration (gaps and islands over
  the authoritative legacy snapshots), leaving `package_set_hash` NULL so
  the first live push runs one full diff.
- **`snapshot_packages` is gone.** Ingest stopped writing it once Q6 was
  resolved, and migration `0004_drop_snapshot_packages` drops it. 0003 is
  unchanged, so its backfill still reads the table before 0004 drops it.

Rough sizing: 100 hosts × 1,500 packages is 150k open rows. Churn is maybe
20 to 200 rows per host per week of routine `apt upgrade`. That is
**well under a million rows per year for 100 hosts**, where option A writes
about 14M rows per *day* at a 15m interval.

### 2.3 Advisory source

**Recommendation: OSV.dev bulk data for the `Debian` and `Ubuntu`
ecosystems as the single ingestion format.** We normalize it into our own
tables. The server never calls OSV per query.

Why OSV over the raw distro feeds:

- **One parser covers both distros.** Debian's data comes from the Debian
  Security Tracker (DSA, DLA, DTSA, plus `DEBIAN-CVE-*` records that
  include **not-yet-fixed** CVEs). Ubuntu's comes from Ubuntu's own security
  team (`USN-*`, plus `UBUNTU-CVE-*` records that also include unfixed
  CVEs). Both use the same JSON schema: `affected[].package.ecosystem` such
  as `Debian:12` or `Ubuntu:22.04:LTS`, the *source* package name, and
  `ECOSYSTEM` ranges with `introduced` and `fixed` events.
- **Distro severity is included**: Debian `urgency` and Ubuntu `priority`
  (negligible, low, medium, high, critical) appear in
  `ecosystem_specific` / `database_specific`. We need these because CVSS
  alone ranks everything "high".
- **CVE aliases and upstream links are included.** These are the join keys
  for CISA KEV and FIRST EPSS, which are keyed by CVE.
- **It extends later.** Alpine, Rocky/Alma and others (Phase 2 RHEL/Alpine
  collectors) are OSV ecosystems too, so no new parser is needed.
- **Refresh is cheap.** OSV publishes a per-ecosystem `all.zip` (initial
  load) and per-record `modified` timestamps, so updates can be incremental.

Trade-offs, and why this is **(judgment call)** Q2:

- OSV is a conversion of the distro data, so it lags the source by hours
  and conversion bugs are possible. The raw Debian tracker JSON
  (`security-tracker.debian.org/tracker/data/json`) is the most
  authoritative Debian source. It has finer statuses (`not-affected`,
  `<no-dsa>`, `<ignored>`, `<postponed>`, `unimportant`) and is one file keyed
  by source package → CVE → release. For Ubuntu, the equivalent is OVAL or
  the Ubuntu CVE tracker.
- **Fallback plan**: keep the normalized tables (§2.4) source-agnostic, so a
  `debian-tracker` importer can replace `osv-debian` later without touching
  matching or the UI.

Enrichment, unchanged from the existing plan:

- **CISA KEV**: JSON catalog, daily
- **FIRST EPSS**: daily CSV, keyed by CVE
- Both land on a per-CVE `cves` row, not per advisory.

Refresh cadence **(judgment call)**:

- OSV incremental sync hourly, full reload weekly (self-healing)
- KEV and EPSS daily
- Only **releases present in `distro_releases` with `supported = true`**
  are imported, to keep the table small. OSV has records back to Debian 3.0.

**As built (P1b, migration 0005).** OSV's per-release ecosystem zips
(`Debian:12/all.zip`, `Ubuntu:22.04:LTS/all.zip`, ...) have been stale
since 2024-10, so the sync reads the **top-level ecosystem directories**
(`Debian/all.zip`, `Ubuntu/all.zip`, plus `modified_id.csv` for
incremental runs) and keeps only affected entries whose ecosystem maps to
a supported release. `Ubuntu:Pro:<ver>` entries map to the same release
with `channel = 'ubuntu-pro'`.

**As built (P2a, Alpine, migration 0016).** `feeds.OSVEcosystems` is
`Debian`, `Ubuntu`, `Alpine`; each top-level directory maps to one
distro (`osv.DistroFor`), and the supported-release fingerprint that
forces a full import is per distro, so enabling an Alpine branch doesn't
reload Ubuntu. Checked 2026-09-28: `Alpine/all.zip` (~4 MB, 4,679
records) and `Alpine/modified_id.csv` are current; the per-release
`Alpine:v3.20/all.zip` is stale since 2024-10 like Debian's, and
`Alpine:v3.22`+ have no per-release directory at all. Records:

- Ids are `ALPINE-CVE-<cve>`, the CVE only in `upstream` (no `aliases`).
  They are per-CVE records like `DEBIAN-CVE-*`: `vuln_key` is the CVE,
  the matcher's per-CVE precedence applies, and their `CVSS_V3` vector
  feeds `cves` (of 4,679 records, 153 carry only `CVSS_V4`, which `cves`
  doesn't store, and 48 no score; the same CVE may still get a v3 score
  from a Debian/Ubuntu record).
- `affected[].package` is the apk **origin** (`pkg:apk/alpine/openssl?arch=source`)
  per branch, ecosystem `Alpine:v3.22` → (`alpine`, `3.22`). Alpine has
  no codenames, so `distro_releases.codename` = `version` = the branch,
  which is also what `purl.ReleaseFor` interns image packages under.
- Ranges are `ECOSYSTEM` with `introduced` (often an upstream version
  without `-rN`, e.g. `3.0.0`, which apk orders below `3.0.0-r0`) and
  `fixed`. There is **no unfixed tracking**: Alpine's secdb lists fixes
  only, so every row is `fixed`. A few ranges list several `fixed`
  events after one `introduced`; the first (lowest) closes the range.
- secdb's `fixed: "0"` ("this branch was never affected") becomes
  `status = 'not_affected'`. On 2026-09-28 every such record in a
  supported branch was also withdrawn.
- **No distro severity**: records carry CVSS only, so
  `distro_severity` is NULL and ranking falls back to KEV/EPSS/CVSS, as
  for an unknown priority.

Live first sync (3.21-3.24 supported): 3,480 advisories (62 withdrawn,
all CVE-keyed), 12,940 affected rows: 3.21 3,096 · 3.22 3,229 · 3.23
3,396 · 3.24 3,219, over ~270-280 source packages per branch; 10 s,
19 MB heap.

**As built (P2a, language ecosystems).** `feeds.OSVEcosystems` also
lists the language directories: `npm`, `PyPI`. A language directory
maps to a package ecosystem, not a distro (`osv.Languages`: OSV `npm` →
`software_versions.ecosystem` `npm`, `PyPI` → `pypi`; `osv.DistroFor` is
`''`), and `osv/language.go` normalizes its records:

- **Rows**: `distro = ''`, `release` = the software ecosystem (`npm`,
  `pypi`), `source_package` = the package name as `software_versions`
  stores it (§4.5: npm `@scope/name`; PyPI PEP 503-normalised, which
  OSV's PyPI names already are), so one (distro, release, source) key never
  mixes two ecosystems' packages of the same name. The matcher maps a
  language package (interned with distro and release `''`) to that key
  (`matcher.AdvisoryScope`), and the `advisory_changes` drain joins
  `('', ecosystem, name)` keys to `software_versions` by ecosystem.
- **Ranges**: `SEMVER` and `ECOSYSTEM` ranges (npm uses `SEMVER`, 54
  entries `ECOSYSTEM`; PyPI `ECOSYSTEM`, 1,567 entries with an extra
  `GIT` range), `introduced` / `fixed` / `last_affected`; `GIT` ranges
  (commits) are skipped. An entry with no usable range falls back to its
  `versions` list, one exact row per version (`introduced` =
  `last_affected` = the version; 129 rows in npm, 180 in PyPI), and
  keeps that list in `raw`. Records list one package per branch
  routinely (minimatch: eight ranges), which the matcher's language rule
  handles (§2.5).
- **Keys**: `vuln_key` is the record's CVE alias when it has exactly one;
  a record citing several is keyed by its own id and matched per CVE (as
  a DSA is); a record without a CVE is keyed by its GHSA id, its own or
  its lowest GHSA alias (a `GO-`/`PYSEC-` record and the GHSA it aliases
  then key one finding), else its own id. npm: 6,054 CVE-keyed, 1,404
  GHSA-keyed; PyPI: 13,168 CVE-, 414 GHSA-, 360 PYSEC-keyed. PyPI has a
  GHSA *and* a PYSEC record for 5,657 of its 6,320 CVEs, both keyed by
  the CVE: one finding citing both ids.
- **Severity**: the GHSA's reviewed severity (record-level
  `database_specific.severity`, lowercased: `critical` / `high` /
  `moderate` / `low`) is the rows' `distro_severity`, so it ranks like a
  distro priority (`severity.ParsePriority`: `moderate` = medium); KEV and
  EPSS still escalate CVE-keyed ones, and CVSS stays the tiebreaker. Its
  `CVSS_V3` vector goes to `cves` under the `vuln_key`: authoritative for
  a GHSA-keyed record (a `cves` row under the GHSA id; `cves` holds the
  enrichment of every `vuln_key`, KEV/EPSS just never match those), and
  only filling in a CVE no distro per-CVE record has scored
  (`Advisory.CVSSIfMissing`), so distro scores win and two GHSAs don't
  flip-flop. A multi-CVE record's single score isn't stored. PYSEC and
  GO records carry no reviewed severity (and GO records no CVSS), so a
  key only they cover ranks "unknown" with KEV/EPSS/CVSS, as an Alpine
  one does. `CVSS_V4`-only records (1,210 npm, 1,129 PyPI) give `cves`
  no score.
- **Shared records**: one GHSA can list packages of several ecosystems
  and then sits in each ecosystem's `all.zip` under the same id (46
  npm/PyPI, 10 npm/Go, 16 PyPI/Go on 2026-09-29). Every language feed
  therefore stores the entries of *every* imported language ecosystem, so
  both feeds write identical content (the second sees an unchanged hash);
  the owner (`advisories.source`) is whichever wrote it last. The set of
  imported languages is in each language feed's fingerprint
  (`osv.FeedFingerprint`): adding one reloads the others. A record that
  leaves one ecosystem's zip but not the other's is deleted by its owner
  and restored by the other feed's next full sync (weekly) at the latest.
- **Malicious packages** (`MAL-*`, OpenSSF): not imported for now. The
  full sync skips them by file name unread, the incremental one before
  fetching or counting them (`OSVStats.malicious`); they would otherwise
  force a full import almost every hour. Of npm's 229,533 records,
  222,028 are `MAL-`; of PyPI's 25,757, 11,787.
- 5 npm rows of 9,754 are dropped as duplicate keys (the same package
  listed twice with the same `introduced`), as for Ubuntu's duplicate
  releases.

Live first syncs (2026-09-29, on a copy of dev data; records = zip
entries including `MAL-`):

| Feed | all.zip | Records | Imported (withdrawn) | Rows / packages | Time | Heap / RSS |
|------|---------|---------|----------------------|-----------------|------|------------|
| npm  | 207 MB  | 229,533 | 7,504 (355)          | 9,749 / 3,593   | 55 s (~50 s download) | 119 / 143 MB |
| PyPI | 33 MB   | 25,757  | 13,947 (543)         | 22,166 / 1,652  | 11 s (~5 s download)  | 43 / 60 MB   |

An immediate incremental run takes 0.2 s.

### 2.4 Advisory schema (replaces `vulnerabilities`)

```sql
-- Which distro releases we understand, and how OSV names them.
CREATE TABLE distro_releases (
    distro          text NOT NULL,           -- 'debian' | 'ubuntu'
    codename        text NOT NULL,           -- 'bookworm', 'jammy'
    version         text NOT NULL,           -- '12', '22.04'
    osv_ecosystem   text NOT NULL,           -- 'Debian:12', 'Ubuntu:22.04:LTS'
    eol_date        date,
    supported       boolean NOT NULL DEFAULT true,
    PRIMARY KEY (distro, codename)
);

-- One row per upstream advisory record, whatever its source.
CREATE TABLE advisories (
    id              text PRIMARY KEY,        -- 'DSA-5532-1', 'DEBIAN-CVE-2024-1234', 'USN-6500-1', 'UBUNTU-CVE-2024-1234'
    source          text NOT NULL,           -- 'osv-debian' | 'osv-ubuntu' (later 'debian-tracker', ...)
    vuln_key        text NOT NULL,           -- canonical id used everywhere else: the CVE alias if any, else id
    aliases         text[] NOT NULL DEFAULT '{}',
    summary         text,
    details         text,
    published_at    timestamptz,
    modified_at     timestamptz NOT NULL,
    withdrawn_at    timestamptz,
    raw             jsonb NOT NULL,          -- full source record, for re-normalizing without re-downloading
    synced_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX advisories_vuln_key_idx ON advisories (vuln_key);

-- Normalized "which source package in which release is affected, fixed in what".
CREATE TABLE advisory_affected (
    advisory_id     text NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    distro          text NOT NULL,
    release         text NOT NULL,           -- codename, via distro_releases.osv_ecosystem
    source_package  text NOT NULL,
    introduced      text,                    -- NULL / '0' = all earlier versions
    fixed_version   text,                    -- NULL = no fix available (yet)
    distro_severity text,                    -- Debian urgency / Ubuntu priority, normalized lowercase
    status          text NOT NULL,           -- 'fixed' | 'unfixed' | 'not_affected' | 'ignored'
    PRIMARY KEY (advisory_id, distro, release, source_package, COALESCE(introduced, ''))
);
CREATE INDEX advisory_affected_lookup_idx ON advisory_affected (distro, release, source_package);

-- Per-CVE enrichment (KEV/EPSS/CVSS). One row per CVE, however many advisories cite it.
CREATE TABLE cves (
    id                 text PRIMARY KEY,     -- 'CVE-2024-1234'
    description        text,
    cvss_v3_score      numeric,
    cvss_v3_vector     text,
    epss_score         numeric,
    epss_percentile    numeric,
    epss_date          date,
    is_kev             boolean NOT NULL DEFAULT false,
    kev_added_at       date,
    kev_due_date       date,
    kev_ransomware     boolean,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE feed_sync_state (
    feed            text PRIMARY KEY,        -- 'osv-debian', 'osv-ubuntu', 'cisa-kev', 'first-epss'
    last_success_at timestamptz,
    last_attempt_at timestamptz,
    cursor          text,                    -- e.g. newest `modified` seen, ETag
    last_error      text
);
```

(The `COALESCE` in a primary key isn't legal as written. In the real
migration, make `introduced` `NOT NULL DEFAULT ''` instead. It is written
this way here for readability.)

**As built (migration 0005)**, differences from the sketch above:

- `advisory_affected` gained `channel` (`standard` | `ubuntu-pro`, part
  of the primary key; Q9), `last_affected` (OSV's rare inclusive upper
  bound, used instead of `fixed`) and `ecosystem` (as published);
  `introduced` is `NOT NULL DEFAULT ''`.
- `advisories` gained `cve_ids` (every CVE the record cites: own id,
  aliases, upstream), `upstream`, `related`, `severity` (record-level
  distro severity, e.g. Ubuntu priority) and `content_hash` (a sync skips
  records whose normalized hash is unchanged); `raw` is trimmed.
- New table **`advisory_changes`** `(distro, release, source_package,
  changed_at)`: the matcher's durable dirty set, written in the same
  transaction as any change to that key's `advisory_affected` rows and
  drained by the `advisory_rematch` job (§2.6).
- **`advisories.vuln_key` rule**: the record's own CVE (a `CVE-` id, or
  the CVE a `DEBIAN-CVE-`/`UBUNTU-CVE-`/`ALPINE-CVE-` record wraps); else the single CVE
  a DSA/DLA/USN cites; else, for a record without a CVE that is or
  aliases a GHSA, that GHSA id (language records, §2.3); else the
  advisory id (a notice citing several CVEs). The matcher then keys *matches* by CVE wherever possible: a
  multi-CVE notice is expanded to each CVE it cites (§2.5 "As built").

**Deduplication across sources.** Debian publishes `DSA-5532-1` *and*
`DEBIAN-CVE-2023-5678` for the same issue. Ubuntu publishes `USN-…` *and*
`UBUNTU-CVE-…`. Everything downstream (matches, findings, UI) is keyed by
**`vuln_key`**, which is the CVE id when there is one. Advisory ids are
kept as a list of references ("fixed by DSA-5532-1") for display and links.
Where the per-CVE record and the DSA disagree on the fixed version, prefer
the per-CVE record, since the tracker is the source the DSA is derived from.
Store both anyway.

### 2.5 The join: version semantics, source vs binary, per-release fixes

**A package version is affected by a vuln_key when all of these hold:**

```
software.distro   = aa.distro
software.release  = aa.release                 -- fixed versions are per codename
software.source_name = aa.source_package       -- advisories are keyed by SOURCE package
aa.status IN ('fixed', 'unfixed')
dpkg_cmp(software.source_version, aa.introduced) >= 0   (or introduced is NULL/'0')
AND (aa.fixed_version IS NULL OR dpkg_cmp(software.source_version, aa.fixed_version) < 0)
```

**Source vs binary.**

- The agent must send `source` and `source_version` from the dpkg `Source:`
  field. Its three forms are:
  - absent: source name = binary name, source version = binary version
  - `Source: openssl`: same version as the binary
  - `Source: openssl (3.0.2-0ubuntu1.15)`: explicit source version, used by
    binNMUs (`+b1`) and some multi-version sources
- Compare the **source version** against the fixed version, because
  advisories give source versions.
- This is an additive field, so no `schema_version` bump is needed. For
  pushes from older agents without `source`, fall back to name = source,
  mark the row `source_inferred = true`, and show "matching may be
  incomplete, update the agent" on the host.
- Kernels are the known hard case. On Ubuntu, `linux-image-*` binaries come
  from `linux-signed-*` or `linux-meta-*` sources, while advisories cite
  `linux`, `linux-hwe-6.8`, `linux-aws` and so on. It needs a small mapping
  (strip the `-signed`/`-meta` infix) plus tests. Open question Q7 covers
  whether to match against *installed* kernels, the *running* one, or both.

**Debian version comparison.** Postgres can't do this natively. Plain text
ordering gets `1.10 < 1.9`, `1.0~rc1 > 1.0` and epochs (`1:2.0` vs `3.0`)
wrong. Recommendation:

- Implement `dpkg --compare-versions` semantics in Go as
  `server/internal/debversion`. It is a port of dpkg's `verrevcmp`:
  - epoch compared numerically
  - upstream version and debian revision compared by alternating
    non-digit and digit runs
  - in non-digit runs, `~` sorts before everything, including end of string;
    letters sort before non-letters
  - digit runs compared numerically

  Use dpkg's own test vectors plus real backport cases (`+deb12u1`,
  `~deb11u1`, `ubuntu0.22.04.1`, `+esm1`).
- **All comparisons happen in Go, and the results are materialized**
  (§2.6). Postgres never compares versions, so no custom extension is
  needed. The official `postgres:18-alpine` image doesn't ship the
  `debversion` extension. We could build a custom image, but that adds
  operational weight to a self-hosted product.
- For later SQL-side needs such as "hosts below version X" in the fleet
  view, a Go-computed **sort key** can be stored on `software_versions`
  (`version_sort_key bytea`): an order-preserving byte encoding of the dpkg
  ordering, compared with `C` collation semantics. It is not needed for
  Phase 1 (open question Q8).

**Ubuntu Pro / ESM.** Hosts attached to Ubuntu Pro receive `+esm` versions
whose fixes are listed in the `Ubuntu:Pro:*` ecosystems. Hosts not
attached should see "fix available only with Ubuntu Pro" rather than a
normal "fix available". This needs one more agent fact: attachment status
from `/var/lib/ubuntu-advantage/status.json` (open question Q9).

**As built (P1b matcher, `server/internal/matcher`).**

- *Predicate* per row, installed source version `v`: out of range if
  `introduced` is set (not `''`/`'0'`) and `v < introduced`; else with
  `fixed`: affected iff `v < fixed`; with `last_affected`: affected iff
  `v <= last_affected` (no fix known); with neither: affected, unfixed.
  Rows with status `not_affected`/`ignored` are skipped.
- *Keys and precedence*: matches are keyed by CVE. For one (source, CVE)
  the **per-CVE record** (`DEBIAN-CVE-`/`UBUNTU-CVE-`/`CVE-`) decides when
  one exists; notices (DSA/DLA/USN/LSN) then only add their ids to
  `advisory_ids`. Without a per-CVE record, the notices citing the CVE
  decide. Within one channel, any row saying the installed version is
  already fixed wins (a regression-update notice doesn't reopen it);
  otherwise the lowest fixed version among affected rows is the fix.
- *Channels (Q9, resolved)*: `ubuntu-pro` rows are matched and labelled,
  never hidden. A standard-channel "not affected/fixed" verdict means no
  match; so does a Pro-channel "fixed" (the host runs an `+esm` build).
  Otherwise, a standard fix wins (`fix_channel = 'standard'`); a fix only
  in Pro gives `fix_channel = 'ubuntu-pro'`, i.e. `requires_pro` ("fix
  requires Ubuntu Pro"); no fix leaves both NULL. Pro attachment is not
  collected yet, so an attached host sees the label until it installs the
  `+esm` build, which then clears the match.
- *Kernels (Q7, resolved)*: `matcher.Resolve` unwraps
  `linux-signed[-X]`, `linux-meta[-X]`, `linux-restricted-modules[-X]`
  (Ubuntu) and `linux-signed[-V]-<arch>` (Debian) to the advisory source
  (`linux`, `linux-hwe-6.8`, `linux-aws`, `linux-6.12`, ...) and compares
  the *binary* version for unwrapped sources (Debian's signed source
  version is `6.1.76+1`; the image's version `6.1.76-1` is the kernel
  source version). Only kernel image/module binaries
  (`linux-image[-unsigned]-<release>`, `linux-modules[-extra]-<release>`)
  are matched, tagged with the `uname -r` release in their name;
  metapackages, headers, tools, `linux-libc-dev`, `linux-source-*`,
  Debian's `bpftool`/`linux-cpupower` etc. are not. Kernels from agents
  that send no `Source:` are not matched (their source can't be derived
  from the name). Findings are raised only for the release in the newest
  snapshot's `kernel_release` (agent `os.kernel`); other installed
  kernels are informational (`host_kernel_packages` view). **Unknown
  running kernel** (agents older than the `kernel` collector, or the
  collector failed): every installed kernel raises findings, marked
  `findings.running_kernel_unknown`, so an unknown never hides risk.

**As built (P2a, comparators per ecosystem).** The predicate and
precedence above are ecosystem-neutral; only version ordering differs.
`matcher.Comparator` (`Validate(v)`, `Compare(a, b) (int, error)`) is
looked up by `software_versions.ecosystem` in one table
(`matcher/ecosystems.go`): `deb` → `debversion`, `apk` →
`server/internal/apkversion`, a port of apk-tools' `version.c`
(digits, one letter, `_alpha _beta _pre _rc` < none < `_cvs _svn _git
_hg _p`, `~hash`, `-rN`; a leading-zero component compares as a
string), tested with apk-tools' own `version.data`. An invalid version
counts as a bad version and is skipped, never ordered by guess (13
distinct values in the whole Alpine feed, e.g. `1999-12-14`). Adding an
ecosystem is one comparator plus its feed. Language ecosystems:

- `npm` → `server/internal/npmversion`: node-semver's `compare` in loose
  mode (three numbers, optional leading `v`/`=`, prerelease identifiers
  numeric < alphanumeric, a prerelease below its release, build ignored,
  numbers capped at `MAX_SAFE_INTEGER`), in-tree because node-semver's
  syntax differs from `golang.org/x/mod/semver`'s (`1.2` is invalid for
  npm); tested with node-semver's comparison and equality fixtures.
- `pypi` → `server/internal/pep440`: PEP 440 as pypa/packaging's
  `Version` (epochs, release with trailing zeros ignored, `a`/`b`/`rc`
  and their spellings, `.post`/`-N`, `.dev`, local versions ordered
  segment-wise), in-tree (one regex, one ordering); tested with
  packaging's own ordering, normalisation and invalid-version vectors,
  and checked equal to packaging 26.3 on all 40,482 valid versions in
  the PyPI feed. Legacy (non-PEP 440) versions are invalid, as in
  packaging ≥ 22: 2,051 distinct feed versions, nearly all in `versions`
  lists (`0.1.0.dev-120828c`), are bad versions, skipped.
- **Range semantics.** A language record lists one range per maintained
  branch (`[0, 3.1.3)`, `[9.0.0, 9.0.6)`, ...), so the distro rule "any
  row saying fixed wins" would call minimatch 9.0.4 fixed because it is
  ≥ 3.1.3. For language ecosystems (the comparator is wrapped in
  `osvRanges`) rows combine as the OSV schema defines them: affected when
  any row of any record citing the key contains the version; the fix is
  the lowest `fixed` among the rows that contain it. Several records for
  one CVE and package (a GHSA and a PYSEC, a GHSA and a GO record) are
  deduplicated by the key and their ranges united, as osv-scanner does;
  every record's id lands in `advisory_ids`.
- `matcher.Assessed`: a language ecosystem is listed with distro `''`, so
  its packages are assessed whatever the (empty) release.

- `matcher.Resolve` matches any ecosystem with a comparator by
  (source, source version) as interned (apk: the origin from the purl's
  `upstream` qualifier, else the binary name, `source_inferred`); the
  kernel mapping and Ubuntu Pro channels stay deb-only.
- `matcher.Assessed(ecosystem, distro, release, supported)` is the
  single answer to "is this package matched at all" (for "not assessed"
  counts): `deb` on debian/ubuntu and `apk` on alpine, with a release
  that `distro_releases` lists as supported; the language ecosystems
  (`npm`, `pypi`) with distro `''`, release ignored. Advisories are imported
  only for supported releases, so a release out of support (Debian 10
  buster) or one not in `distro_releases` matches nothing and its
  packages are "not assessed", never "no vulnerabilities"
  (`matcher.ReleaseStatus`: supported / out_of_support / unknown).
  Migration 0019 lists common end-of-life Debian, Ubuntu and Alpine
  releases (`supported = false`, with their EOL date) so the dashboard
  can say "out of support since ..." rather than "not recognised".
- The store joins `advisory_affected` on (distro, release,
  source_package) exactly as for deb: an apk package in an Alpine 3.22
  image is (`alpine`, `3.22`, origin).
- `matcher.Version` 2: apk versions interned before this were stamped
  "evaluated, nothing to match" under 1; the bump re-evaluates them.
  deb results are unchanged. 3: `Assessed` needs a supported release;
  matches are unchanged, the bump re-scores image lists. 4: npm
  packages are matched. 5: PyPI packages are matched.
- Host findings (`findings.Build`) still pick the lowest installed
  version with debversion; hosts only send deb today.

### 2.6 Materialized or computed on read?

**Recommendation: materialize matches per `software_versions` row. Compute
host exposure on read. Materialize per-host findings for lifecycle and
alerting.**

```sql
-- Interned, immutable package versions (fleet-wide). §2.2.
CREATE TABLE software_versions (
    id                bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ecosystem         text NOT NULL,            -- 'deb' now; later 'rpm','apk','homebrew','macos-app','macos-pkg','windows-program'
    distro            text NOT NULL DEFAULT '', -- 'debian' | 'ubuntu' | '' for non-distro ecosystems
    release           text NOT NULL DEFAULT '', -- codename
    name              text NOT NULL,            -- binary package / app / program name
    version           text NOT NULL,
    arch              text NOT NULL DEFAULT '',
    source_name       text,                     -- deb only
    source_version    text,                     -- deb only
    source_inferred   boolean NOT NULL DEFAULT false,
    attrs             jsonb NOT NULL DEFAULT '{}', -- ecosystem extras (Windows publisher, macOS bundle id, ...)
    -- matching bookkeeping
    matcher_version   int,                      -- NULL = never evaluated
    evaluated_at      timestamptz,
    max_fixed_version text,                     -- highest fixed_version across open matches (Go-computed), for "upgrade to" hints
    UNIQUE (ecosystem, distro, release, name, version, arch)
);
CREATE INDEX software_versions_source_idx ON software_versions (distro, release, source_name);
CREATE INDEX software_versions_name_idx ON software_versions (name text_pattern_ops);

-- Host inventory history as validity ranges. §2.2.
CREATE TABLE host_software (
    host_id                 uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    software_id             bigint NOT NULL REFERENCES software_versions(id),
    first_seen_at           timestamptz NOT NULL,
    first_seen_snapshot_id  uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    removed_at              timestamptz,        -- NULL = currently installed
    removed_snapshot_id     uuid REFERENCES snapshots(id) ON DELETE SET NULL,
    PRIMARY KEY (host_id, software_id, first_seen_at)
);
CREATE UNIQUE INDEX host_software_current_uq ON host_software (host_id, software_id) WHERE removed_at IS NULL;
CREATE INDEX host_software_by_software_idx ON host_software (software_id) WHERE removed_at IS NULL;
CREATE INDEX host_software_changes_idx ON host_software (host_id, first_seen_at DESC);
CREATE INDEX host_software_removals_idx ON host_software (host_id, removed_at DESC) WHERE removed_at IS NOT NULL;

-- Positive matches only: no row means not known vulnerable.
CREATE TABLE software_vulnerabilities (
    software_id      bigint NOT NULL REFERENCES software_versions(id) ON DELETE CASCADE,
    vuln_key         text NOT NULL,             -- CVE id or advisory id
    advisory_ids     text[] NOT NULL,           -- all sources citing it: {'DSA-5532-1','DEBIAN-CVE-2023-5678'}
    fixed_version    text,                      -- NULL = no fix available
    fix_channel      text,                      -- NULL | 'ubuntu-pro'
    distro_severity  text,
    matcher_version  int NOT NULL,
    matched_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (software_id, vuln_key)
);
CREATE INDEX software_vulnerabilities_vuln_idx ON software_vulnerabilities (vuln_key);
```

Why this split:

- **Per-version materialization is small and stable.** It changes only when
  a new version appears or advisories change. It does not change when a host
  pushes. Evaluating "openssl 3.0.2-0ubuntu1.15 on jammy" once serves every
  host that has it.
- **Host exposure is a plain indexed join**:
  `host_software (current) ⋈ software_vulnerabilities ⋈ cves`. There is
  nothing to keep in sync per push, and old inventories are re-evaluated
  automatically. "Was host X vulnerable to CVE-Y on date D?" uses the same
  join with a range predicate, against *today's* advisory knowledge. That is
  exactly the retroactive property the user asked for.
- **`findings` stays materialized** because it carries lifecycle
  (`first_seen_at`, `resolved_at`, open or resolved) and drives alerts.
  Findings are one per `(host, source package, vuln_key)`, not per binary,
  so one openssl CVE doesn't raise separate alerts for `libssl3`, `openssl`
  and `libssl-dev`.
  `dedup_key = 'pkg:' || source_name || ':' || vuln_key`.
  Change `findings.vulnerability_id` to reference `cves(id)`, or make it
  plain `vuln_key text`, since not every vuln_key is a CVE.

**When matches are recomputed** (a Postgres-backed job queue, see Q10):

| Trigger | Scope |
|---|---|
| A new `software_versions` row is interned at ingest | That one version |
| Advisory sync inserts, updates or withdraws `advisory_affected` rows | All versions with the same `(distro, release, source_package)` |
| KEV/EPSS refresh | No re-match; only `severity_rank` on open findings, which is a cheap UPDATE |
| `matcher_version` bumped (comparator or normalization fix) | All versions with `matcher_version < current`, in batches |
| A new release is marked `supported` in `distro_releases` | All versions in that release |

After re-matching a version, **reconcile findings** for every host that
currently has it. Open new `(host, source, vuln_key)` findings. Resolve
findings whose vuln no longer matches any installed version, because the
host upgraded or the advisory was withdrawn or marked `not_affected`. The
ingest diff (§2.2) also triggers reconciliation for the host when its
package set changed. Findings reconciliation is the only per-host write, and
it happens only on change.

**Severity ranking** (`findings.severity_rank`), keeping the existing
"KEV and EPSS first" principle, extended with distro severity:

1. KEV listed
2. EPSS percentile
3. distro severity (Ubuntu priority / Debian urgency; `negligible` and
   `unimportant` sink to the bottom)
4. CVSS as a tiebreaker
5. "no fix available" shown separately, not hidden

The exact formula is a later task. Put it in one Go function that is
unit-tested.

**As built (P1b, migration 0007).** The matcher (`store/matching.go`)
writes `software_vulnerabilities` per version (replacing a version's
rows only when its match set changed) with `fixed_version`,
`fix_channel` (NULL = no fix, `standard`, `ubuntu-pro`),
`fix_advisory_id`, `advisory_ids`, `distro_severity`; and stamps
`software_versions.match_source` / `match_version` / `kernel_release` /
`matcher_version` / `evaluated_at` / `max_fixed_version` (highest
standard-channel fix). Triggers are as in the table above: ingest
enqueues `match_versions` in the snapshot transaction; `advisory_rematch`
drains `advisory_changes` (delete a key only if its `changed_at` still
equals the value read); `matcher_sweep` evaluates `matcher_version IS
NULL OR < matcher.Version` on start and every 5 minutes. A version whose
matches changed queues `reconcile_host` for every host having it; ingest
also queues it when ranges opened/closed or the running kernel changed.
Findings carry a snapshot for display and ranking (installed/fixed
version, `fix_channel`/`requires_pro`, `advisory_ids`, distro severity,
`severity` bucket, `severity_rank` = bucket as int, `severity_key` =
`severity.Key` as bigint for `ORDER BY`, KEV/EPSS/CVSS, `software_ids`,
`packages`, `kernel_release`) and lifecycle columns (`first_seen_at`,
`last_seen_at`, `resolved_at`, `reopened_at`, `reopen_count`). KEV, EPSS
and CVSS changes don't re-match: `findings_rerank` recomputes severity
for open findings whose `cves` row changed since the sync started.

**Image findings and scores (P2a, migration 0015).** Container image
package lists (§4.5) are in `software_versions`, and nothing in the
matcher was host-only: `match_versions`, `advisory_rematch` and
`matcher_sweep` evaluate image versions by (distro, release, source)
exactly like host ones. What was host-only was the fan-out after a
version's matches change (`HostsWithSoftware`); it now also re-scores
every ok list holding the version (`image_software` reverse index) and
queues `reconcile_host` for hosts having such an image
(`HostsWithImageSoftware`).

- *Findings, kind `vulnerable_image`*: one per (host, image, source
  package, vuln_key), `dedup_key = 'img:<image_id>:<source>:<vuln_key>'`.
  Scope: an image present on the host (open `host_images` range,
  inspected, so its platform key is known) that at least one current
  container on the host uses (open `host_containers` range, any state,
  same `image_id`). An image with no container gets a score only. The
  package list is `image_sbom_effective(host owner)`: the server's list,
  else the owner's agent list, never another user's. Grouping, snapshot
  columns, severity and lifecycle are the package ones
  (`findings.BuildImage` shares `findings.Build`'s grouping; one
  `findings.Reconcile` over both kinds in the same `reconcile_host`
  transaction), plus `image_id`/`image_os`/`image_arch`/`image_variant`,
  `image_refs` (repo tags on the host, digests when untagged) and
  `container_names`. Kernel binaries inside an image never raise
  (containers run the host's kernel). The lowest installed version per
  group is chosen with the ecosystem's comparator
  (`matcher.ComparatorFor`). `reconcile_host` snoozes while an in-scope
  list has unevaluated versions, as for host packages.
- *Triggers*: a list written (`WriteImageSBOM` with
  `jobs.EnqueueAfterImageSBOM` queues `reconcile_image{key}` in its
  transaction: score the key's lists, snoozing until matched, then
  `reconcile_host` for every host having the key); a version's matches
  changed (above); ingest opened/closed a container or image range
  (`SnapshotResult.ImageUseChanged`); KEV/EPSS/CVSS changes
  (`findings_rerank` re-ranks both kinds and re-scores lists matched to
  the changed CVEs).
- *Scores*: `image_sbom_scores` per list (so identical for every user
  seeing it): worst bucket, counts per bucket, top `severity_key`, KEV
  count, fixable count, max CVSS, package count and `not_assessed_count`
  (packages outside `matcher.Assessed`, the single Go list of assessed
  ecosystems, including every distro package of a release out of support
  or unknown). Computed in Go
  (`findings.ScoreOf`, the finding grouping) because buckets come from
  `severity.Assess`; never written while versions are unevaluated.
  `image_score_sweep` (worker start + matcher cadence) scores lists whose
  score is missing, older than the list, or from an older
  `matcher.Version` (coverage changes bump it), or that count
  vulnerabilities but have no `image_sbom_vulns` rows (lists scored
  before migration 0018: the backfill).
- *Rows* (`image_sbom_vulns`, migration 0018): the groups a score
  counts, one per (list, source package, vuln_key), written by
  `ScoreImageSBOM` in the same transaction as the score and replaced as
  a whole: representative row (lowest installed version by the
  ecosystem comparator: installed / fixed version, fix channel and
  advisory, distro severity, ecosystem), binaries and their
  `software_versions` ids, advisory ids, the assessed bucket / rank /
  `severity_key` and the KEV / EPSS / CVSS it was assessed with. So the
  ranking rules have one copy, in Go: the dashboard lists these rows,
  they add up to `image_sbom_scores`, and a row's key equals its
  `vulnerable_image` findings'. Current only while the score is
  (`computed_at >= image_sbom_state.updated_at`); readers check that.
- *Read model*: `image_scores(user)` per `container_images` key: list
  status (`ok` / `unavailable` / `error` with reason / `none` = never
  attempted), source, and the effective list's score, with `scored`
  false until a current score exists. Clean = ok, scored, 0 vulns, 0 not
  assessed; no list is never clean. Inlined by the planner; callers
  restrict to the user's hosts' images (fleet) or one host's
  (`store.FleetImageScores`, `HostImageScores`, `ImageScoreOf`, and the
  SQL examples in the migration).

---

## 3. Packages in the dashboard

This follows the existing pattern in [decisions/direct-postgres-reads.md](decisions/direct-postgres-reads.md): **Next.js Server
Components read Postgres directly** through `web/src/lib/queries*.ts`.
None of the views below needs a new Go HTTP endpoint. The Go side writes
`host_software`, `software_vulnerabilities` and `findings`, and Next.js
reads them. Every query is scoped by `hosts.user_id = session.user.id`.

Filters, sorting, paging and search live in **URL search params**, so views
are shareable, work with the back button, and render on the server. The
existing shell has `Table`, `Badge`, `Sheet`, `Input`, `Command` and
`Tooltip`. It still needs shadcn `tabs`, `select` (or a popover faceted
filter) and a small pagination component. Tables use the shadcn data table
(`@tanstack/react-table`) in its server-driven mode, state in URL params
(Q11, resolved).

### 3.1 Navigation (sidebar `navGroups` in `web/src/components/layout/app-sidebar.tsx`)

```
General
  Overview          /dashboard
  Hosts             /dashboard/hosts            (machine list; built with P1.5 management)
  Vulnerabilities   /dashboard/vulnerabilities
  Packages          /dashboard/packages
  Agents            /dashboard/agents           (deployed collectors, after the split in §4)
```

As built, Agents sits under General next to Hosts (no Settings group yet);
host detail pages hang off `/dashboard/hosts/[hostId]`.

### 3.2 Host detail shell: `/dashboard/hosts/[hostId]/layout.tsx`

- **Header**:
  - hostname and label
  - OS badge (for example `Ubuntu 22.04 (jammy)`; later a Windows or macOS
    icon)
  - last seen
  - reporting agent
  - pills for reboot pending, open vulns and KEV count
- **Tabs, as links**: Overview · Packages · Vulnerabilities · History ·
  Ports (later Services)
- **Query**: `getHost(userId, hostId)` returns host, latest snapshot
  scalars and finding counts. It returns 404 if the host is not owned by the
  user.

**As implemented (P1c).** The header shows OS, last seen, reboot pill,
open-vulnerability count with top severity, a KEV count pill, and the
running kernel (newest snapshot by `collected_at`, as the
`host_kernel_packages` view uses) or an explicit "Running kernel
unknown". Counts come from `getHostVulnSummary` (open/resolved
`vulnerable_package` findings, React-cached per request) rather than
`getHost`. Tabs: Overview · Packages · Vulnerabilities (with count) ·
History. `requireHost()` gates the layout and every tab page.

### 3.3 Per-host packages: `/dashboard/hosts/[hostId]/packages`

Search params:

- `q` (name or source prefix)
- `status` = `all` | `vulnerable` | `no-fix` | `ok`
- `severity` = `kev` | `critical` | `high` | …
- `sort` = `name` | `severity` | `installed`
- `page`
- `at` = ISO date for point-in-time view (optional)

| Column | Source |
|---|---|
| Package: binary name, with source name in muted text when different | `software_versions.name`, `.source_name` |
| Installed version (mono) | `.version` |
| Arch | `.arch` |
| Status: `Up to date` / `Vulnerable (n)` / `No fix yet (n)` / `Pro fix` | count of `software_vulnerabilities`, split by `fixed_version IS NULL` and `fix_channel` |
| Top severity: KEV badge, EPSS %, distro priority | max over the package's matches ⋈ `cves` |
| Fixed in ("upgrade to") | `software_versions.max_fixed_version` |
| Installed since | `host_software.first_seen_at` |

- **Row click** opens a `Sheet` listing that package's vulnerabilities:
  - CVE id, linked to `/dashboard/vulnerabilities/[vulnKey]`
  - summary
  - KEV, EPSS, CVSS, distro severity
  - fixed version
  - advisory links (DSA/DLA to `security-tracker.debian.org`, USN to
    `ubuntu.com/security/notices`)
- **Default sort** is vulnerable-first by severity rank, then name.
- **Point-in-time**: `?at=2026-06-01` swaps the "current" predicate for the
  range predicate and shows a banner ("Inventory as of 1 Jun 2026, matched
  against today's advisories").

```sql
-- getHostPackages(userId, hostId, filters)
SELECT sv.name, sv.source_name, sv.version, sv.arch, hs.first_seen_at, sv.max_fixed_version,
       count(m.vuln_key)                                   AS vuln_count,
       count(m.vuln_key) FILTER (WHERE m.fixed_version IS NULL) AS nofix_count,
       bool_or(c.is_kev)                                   AS any_kev,
       max(c.epss_percentile)                              AS max_epss
FROM hosts h
JOIN host_software hs      ON hs.host_id = h.id AND hs.removed_at IS NULL   -- or range predicate for ?at=
JOIN software_versions sv  ON sv.id = hs.software_id
LEFT JOIN software_vulnerabilities m ON m.software_id = sv.id
LEFT JOIN cves c           ON c.id = m.vuln_key
WHERE h.id = $2 AND h.user_id = $1
  AND ($3::text IS NULL OR sv.name LIKE $3 || '%' OR sv.source_name LIKE $3 || '%')
GROUP BY sv.id, hs.first_seen_at
ORDER BY any_kev DESC NULLS LAST, max_epss DESC NULLS LAST, sv.name
LIMIT 100 OFFSET $4;
```

**As implemented (P1c).** Status comes from findings, not raw matches:
open `host_software` rows join `host_package_vuln_status` on
`(host_id, software_id)` (open findings, top severity, KEV / fixable /
Pro-only / unfixed counts), plus a lateral count of
`software_vulnerabilities` for the version ("known" matches). Status
reads "Vulnerable (n)" with "n no fix yet · n fix requires Pro", or, for
a kernel known not to be the running one, "Not the running kernel (n)"
(informational). Params: `status` = `vulnerable` | `kev` | `no-fix`,
`sort` = `severity` (default: top `severity_key`, then count, then
name) | `name`. "Fixed in" is `software_versions.max_fixed_version`.
Under `?at=` the findings join is off and status/filters use the
version's matches against today's advisories (the banner says so).
The row sheet is `?pkg=<software_id>`: honoured only if this host has
(or had) that version in `host_software`, else 404; it lists
`software_vulnerabilities` for the version with severity from this
host's open finding (`$sid = ANY(software_ids)`), KEV/EPSS/CVSS, fix
and advisory links.

### 3.4 Per-host change history: `/dashboard/hosts/[hostId]/history`

Search params: `from`, `to` (default: last 30 days), `q`, `type` =
`installed` | `upgraded` | `downgraded` | `removed`.

Grouped by day, then by snapshot time. This is the "what did last night's
unattended-upgrades do" view.

| Column | Notes |
|---|---|
| Time | the snapshot's `collected_at` (first_seen / removed) |
| Change | Installed / Upgraded / Downgraded / Removed. Upgrade vs downgrade uses `dpkg_cmp`, done in Go at write time and stored (see below) or computed in the Server Component with a TS port. |
| Package | binary name (source name muted) |
| From → To | versions |
| Security effect | "Fixed 3 CVEs (1 KEV)" / "Introduced 1 CVE": set difference of `software_vulnerabilities` between old and new versions |

Query: two sides unioned. `host_software` rows with `first_seen_at` in the
window (adds) and rows with `removed_at` in the window (removes). They are
paired on `(name, arch, snapshot id)` into upgrades and downgrades.

Recommendation **(judgment call)**: have the Go ingest diff also write a
thin `host_software_changes` row
`(host_id, snapshot_id, at, name, arch, from_software_id, to_software_id, kind)`.
The pairing and the dpkg comparison then happen once, in Go, and the page is
a simple indexed range scan. It is derived data, rebuildable from
`host_software` at any time, so it doesn't compete with the ranges as a
source of truth.

A small "packages changed" sparkline on the host Overview tab can use the
same table.

**As implemented (P1c).** Computed on read, no `host_software_changes`
table. Changes are paired per boundary as before; deb pairs are
classified Upgraded / Downgraded with a TS port of dpkg ordering
(`web/src/lib/debversion.ts`, verified against the Go package's dpkg
vectors; unparseable versions and other ecosystems stay "Changed").
"Security effect" is "Fixed N (k KEV)" / "Introduced N": the
`software_vulnerabilities` set difference between the two versions, one
query per page, labelled as today's advisory knowledge. No `type`/`from`/
`to` filters yet; cursor paging by boundary.

### 3.5 Per-host vulnerabilities: `/dashboard/hosts/[hostId]/vulnerabilities`

This is the existing task item ([tasks/phase-1c-packages-ui.md](tasks/phase-1c-packages-ui.md)) "findings list/detail page", now scoped per
host. There is one row per open finding, `(source package, vuln_key)`:

| Column | Source |
|---|---|
| Vulnerability (CVE id + summary) | `findings.vuln_key` ⋈ `advisories` / `cves` |
| Severity: rank badge, KEV, EPSS %, distro priority, CVSS | `cves`, `software_vulnerabilities.distro_severity` |
| Package (source), affected binaries | `findings.details` or live join |
| Installed → Fixed | installed source version, `fixed_version` or "no fix yet" |
| Detected | `findings.first_seen_at` |

There is a toggle for `status=resolved` (history: "fixed on 12 Sep by
upgrading openssl").

**As implemented (P1c).** One row per open finding
`(source package, vuln_key)`, `ORDER BY severity_key DESC, vuln_key`;
columns vulnerability (+ CVE description), severity badge + KEV + EPSS/
CVSS/distro priority, source package + binaries, installed, fixed in
(or "No fix yet" / "Fix requires Ubuntu Pro"), detected (reopened
noted). `status=resolved` lists resolved findings by `resolved_at`.
Filters `q`, `severity`, `kev=1`, `fix` = `available` | `pro` | `none`,
`sort` = `severity` | `recent`. `?v=<vuln_key>` opens a sheet (404 if
this host has no finding for it) with the `cves` row (description, KEV
dates, EPSS, CVSS vector) and the finding's `advisories`. A kernel panel
above the table lists `host_kernel_packages` grouped by kernel release
(running / not running · info only / running state unknown), and
explains that findings cover every installed kernel while the running
kernel is unknown.

**With container images (P2a, as built).** The tab also lists the
host's `vulnerable_image` findings (images a current container on the
host uses, §2.6), one row per finding, in a server-mode DataTable
(`getHostVulnList`, `web/src/lib/queries-vuln-list.ts`; URL state
`hostVulnsTable()` in `web/src/lib/vuln-tables.ts`): `?q` (CVE, package,
binary, image ref or container name), facets `kind` = `package` |
`image` (none = both), `severity`, `kev=1`, `fix` = `available` | `pro`
| `none`, sort `severity` | `vuln` | `seen` (first seen when open,
resolved at when resolved; the resolved default). A **Where** column
says where the finding is: a host package (source package, binaries,
installed version) or an image (first ref, else the short id; platform;
container names; the package and version inside the image) linking to
the image page's Vulnerabilities tab filtered to the CVE
(`imageHref(..., {platform, tab: "vulnerabilities", q, host})`, the shape
of `store.ImageFindingURL` plus the platform). The fix column for an
image reads "Rebuild or re-pull image; fixed in <version>". Counts are
per kind and never summed: one line per kind above the table (open or
resolved count, severity badges and KEV, each narrowing to that kind),
two pills on the tab (host packages, and container images with an
icon). The host header's severity badge and the Overview tab's
Vulnerabilities card stay host-package counts (the card links
`?kind=package` and adds a separate container-images line); its "Most
urgent" ranks both kinds. The `?v=` sheet lists both kinds.

### 3.6 Fleet-wide views

**`/dashboard/packages`**. Search box first (`?q=openssl`), no giant
unfiltered list. Results are grouped by package name:

| Package | Versions in fleet | Hosts | Vulnerable hosts |
|---|---|---|---|

Drill down to **`/dashboard/packages/[name]`**. It has a versions table
(version, release, host count, vuln count, "fixed in") and a hosts table:

| Host | Release | Installed version | Since | Status |
|---|---|---|---|---|

Query: `software_versions WHERE name = $1` ⋈ `host_software (current)` ⋈
`hosts WHERE user_id = $1`, grouped by version.

**`/dashboard/vulnerabilities`**. Fleet CVE list. Filters: `kev`,
`severity`, `fix` = `available` | `none`, `q` (CVE id or package).

| Vulnerability | Severity (KEV/EPSS/priority) | Affected hosts | Packages | Fix available | First seen in fleet |
|---|---|---|---|---|---|

Query: open `findings` for the user's hosts, grouped by `vuln_key`, joined
to `cves`.

**`/dashboard/vulnerabilities/[vulnKey]`**. The CVE detail page:

- description, KEV/EPSS/CVSS
- all advisories with links
- per-release fixed versions (from `advisory_affected`)
- **affected hosts** table: host, package, installed, fixed in, since
- a "previously affected" toggle: hosts that had a vulnerable version at
  some point and have since upgraded. This is answered from
  `host_software` ranges, so it covers hosts that were vulnerable *before*
  the CVE was even published. This is the payoff of keeping history
  server-side.

**Overview (`/dashboard`)**. It is currently a placeholder. Stat cards:

- hosts reporting / stale
- hosts with KEV vulns
- open vulns (fix available vs none)
- reboots pending

Plus a "top 5 vulnerabilities by rank across fleet" table and "recent
package changes across fleet".

**As implemented (P1c).**
- `/dashboard/vulnerabilities`: the user's findings grouped by
  `vuln_key`: affected hosts (open), previously affected (resolved),
  top severity, KEV, EPSS/CVSS, source packages, fix availability
  (any standard fix / some Pro-only / some unfixed), first seen.
  `status=resolved` shows "resolved everywhere" (no open finding left).
  Same filters as the host tab plus `sort=hosts|recent`. The "Vulnerable
  hosts" column on `/dashboard/packages` is not built.
- `/dashboard/vulnerabilities/[vulnKey]` (key validated, 404 when no
  `cves` row, advisory or finding of this user exists): CVE facts,
  affected hosts (open findings), affected versions currently installed
  on the user's hosts (`software_vulnerabilities` ⋈ open
  `host_software` ⋈ the user's `hosts`; non-running kernels appear here
  without a finding), previously affected (resolved findings; not yet
  from inventory ranges), per-release fixes from `advisory_affected`
  (capped at 200 rows) and all advisories
  (`vuln_key = $1 OR cve_ids @> ARRAY[$1]`, so the GIN index is used).
- Overview (`/dashboard`): hosts (not seen in 24h), open findings and
  distinct vulns, KEV findings and hosts, reboot pending (newest
  snapshot), findings by severity, fix available / Pro-only / no fix,
  top 5 vulnerabilities. No "recent package changes" feed yet.
- Overview with container images (P2a): host numbers and image numbers
  are shown side by side, never summed (an image is fixed by rebuilding
  or re-pulling it, a host package by upgrading the host). The host
  cards and bars count `vulnerable_package` only and say "Host
  packages". The **Container images** section
  (`web/src/lib/queries-overview-images.ts`,
  `web/src/components/overview/image-section.tsx`) starts from the
  user's current `host_images` on non-archived hosts (inspected keys)
  joined to `image_scores(user)`: images with vulnerabilities of images
  scored; open `vulnerable_image` findings with image, host and KEV
  counts and severity bars; the 5 most vulnerable images a current
  container uses (the list's `top_severity_key`, then vuln count) with
  `ImageScoreCell`, hosts and containers; and one line of images not
  scored (`imageScoreState`: local/private = needs the agent, other
  `unavailable` = no SBOM, `error` = fetch failing, none / scoring =
  waiting). No current image or container at all: a single line linking
  to Images instead of the section. "Most urgent vulnerabilities" groups
  open findings of both kinds by `vuln_key` (same `severity_key`
  ranking) and badges where each is: "Host package" (packages, hosts)
  and/or "Image" (the image or image count, packages, hosts). The CVE
  link goes to the CVE page when a host package is affected, else to
  the single image's Vulnerabilities tab filtered to the CVE (several
  images: the CVE page). "View all" opens the fleet list with no kind
  filter; the host package cards, bars and the KEV "Needs attention"
  item link with `kind=package`, the Container images section's
  findings, KEV and bars with `kind=image`, so the list matches the
  number clicked.
- Fleet list with container images (P2a): `/dashboard/vulnerabilities`
  lists `vulnerable_package` and `vulnerable_image` findings in one
  server-mode DataTable (`getFleetVulnList`,
  `web/src/lib/queries-vuln-list.ts`; URL state `FLEET_VULNS_TABLE`).
  Rows: one per `vuln_key` for host packages (grouped across hosts, as
  before) and one per (`vuln_key`, image key) for images, since each
  image is its own fix. Facets `kind` (`package` | `image`, none =
  both), `severity`, `kev=1`, `fix`; sort `severity` | `vuln` | `hosts` |
  `first_seen`; `?q` also matches image refs and container names.
  **Where**: host package source packages, or the image (first ref,
  platform, containers) linking to the image page's Vulnerabilities tab
  filtered to the CVE. Fix: host rows as before ("Upgrade available" /
  Pro / no fix), image rows "Rebuild or re-pull image; fixed in
  <package> <version>". `status=resolved` is per row: a CVE fixed in
  host packages but still in an image is resolved in one row and open
  in the other. Above the table, one card per kind (distinct CVEs,
  hosts, images, KEV findings), never summed; each links to that kind.
- CVE page with container images: "Host packages on hosts" (as before)
  and **Container images**: one row per image key with a
  `vulnerable_image` finding for the CVE on the user's hosts (image
  linking to its Vulnerabilities tab filtered to the CVE, platform,
  package + installed version, severity/KEV, hosts with their
  containers, fix, since; resolved images badged), client-mode
  DataTable. The header says where separately ("In host packages on N
  of your hosts", "In M container images on K hosts"); the severity
  badge is the worst of both kinds.
- Sidebar badge (`queries-nav.ts` `vulnsUrgent`): distinct KEV or
  critical CVEs in host packages only. A single number can't show both
  kinds and they are never summed; urgent images have their own "Needs
  attention" item on the Overview.
- Severity colours live in one component
  (`web/src/components/vuln/badges.tsx`).

### 3.7 Query and index notes

- All host-scoped queries go through `hosts.user_id`. Add
  `CREATE INDEX hosts_user_id_idx ON hosts(user_id)`, which doesn't exist
  today.
- The fleet package search uses
  `software_versions_name_idx (text_pattern_ops)` for prefix search. Add
  `pg_trgm` only if substring search is wanted.
- Nothing here needs caching at MVP scale. The existing
  [decisions/direct-postgres-reads.md](decisions/direct-postgres-reads.md) guidance applies if it ever does.

### 3.8 Container images (P2a, as built)

**Image detail: `/dashboard/images/-/<image id>`** (folder
`web/src/app/dashboard/images/-/[imageId]`; key and URL rules in
`web/src/lib/image-key.ts`). The key is `container_images`'
(image_id, os, arch, variant): `?platform=linux/arm64/v8` selects it,
else the platform the image has on `?host=`, else the user's first (a
platform switcher lists the others). `?tab=vulnerabilities` switches tabs.
Tenancy: every read starts from the user's current `host_images`
(`getImagePlatforms`, 404 otherwise), and package lists are only read
through `image_sbom_effective(user)`, never by list id.

- *Header* (`queries-image.ts`): tags and digests across the user's
  hosts, platform, created, distro (`image_sbom_state.distro_name` /
  release), list source + tool + generated_at, the score from
  `image_scores(user)`, and every host with the image and the containers
  using it (score only when none).
- *Packages tab* (`queries-image-packages.ts`): every package of the
  effective list, server-driven DataTable (`?q` name/source/path, facets
  `?ecosystem=` and `?status=vulnerable,not-assessed,pending,no-known`,
  `?sort=status|name|ecosystem`, paging). Not assessed = outside
  `matcher.Assessed` (mirrored in `web/src/lib/assessed.ts`, which
  takes the release's `distro_releases.supported` too): never "no
  vulnerabilities".
- *Vulnerabilities tab* (`queries-image-vulns.ts`): the effective
  list's `image_sbom_vulns` rows (§2.6 "Image findings and scores"), one
  per (source package, vuln_key) as `ScoreImageSBOM` grouped and
  assessed them (kernel binaries skipped), so images no container uses
  work too; per row the user's `vulnerable_image` findings (host, open
  since / resolved). Facets severity, KEV, fix; sort severity (default),
  vuln, package, EPSS, CVSS. Read only while the list's score is
  current; until then the tab says matching is in progress.
- *Severity per row*: the bucket and `severity_key` Go wrote; the web
  never re-derives the ranking rules (the former SQL mirror of
  `severity.Assess` is gone). Rows add up to `image_sbom_scores` and
  keys equal `findings.severity_key` (checked on real data 2026-09-29:
  1021 rows over 6 lists, 290 open findings). A Packages tab row's worst
  severity is the worst of the rows whose `software_ids` hold it.
- *States instead of empty tables* (`list-state.tsx`): not inspected on
  any host (no platform), no package list yet, local image (no repo
  digest) needs the agent, `unavailable` with its reason verbatim
  ("private or local image, needs the agent", "registry has no SBOM
  attestation for this image", ...), error with the retry time, release
  not assessed (release out of support with its EOL date, release not
  recognised, or distro not imported), matching in progress (list ok,
  score not current). The same "release out of support" state (never the
  green "no known vulnerabilities") is what score cells, the image
  header and the Overview's container images section show
  (`imageScoreState` kind `release_not_assessed`; the Overview counts
  such images apart from scored ones).

**Score columns** (`components/image/score-cell.tsx`, `ImageScoreCell`):
worst bucket with its count, KEV count, total and max CVSS, or the state
label; linked to the detail page. Host Images and Containers tabs join
`image_scores(user)` per row; the fleet Images page shows each
repository's most urgent image (`getRepoScores`, "worst of N images"),
and the repository page links each image to its detail page.
Notification links for `vulnerable_image` findings point at the detail
page's Vulnerabilities tab filtered to the CVE (`store.ImageFindingURL`).

---

## 4. Domain model: agents, hosts, OS families

### 4.1 Target concepts

| Concept | Meaning |
|---|---|
| **Agent** | One deployed collector process with its own credential. It belongs to a user (later an org). It reports its own version and platform. |
| **Host** | One monitored machine, with an OS family (`linux` / `windows` / `macos`) and an identity that survives agent reinstalls. This is what vulns, packages and findings hang off. |
| **Assignment (`agent_hosts`)** | "This agent collects this host, in this mode." It is many-to-many in the schema. The normal case is one agent with one `local` host. A subnet agent has one local host plus N `remote` hosts. |
| **Snapshot** | One collection of one host by one agent at one time. It records *both* `host_id` and `agent_id`. |

### 4.2 Collection modes

- **`local`** (all that exists today). The agent runs on the host and reads
  its facts directly: Linux files under `/host`, the Windows
  registry/SCM/WMI, macOS plists. It preserves the current principle:
  **no command execution, no inbound ports**.
- **`remote`** (proposed, later). The agent reaches another machine over
  the network with credentials, using `ssh` for Linux/macOS or `winrm` for
  Windows, and runs a **fixed, compiled-in, read-only** set of reads. On
  Linux those are `cat /var/lib/dpkg/status`, `cat /etc/os-release`,
  `ss -Htln` and similar.
  - This **changes the security story**. The agent now holds credentials to
    other machines and executes commands on them. The principle has to
    become "the *server* can never cause code execution anywhere; the agent
    only runs its own hard-coded read-only probes". That is a product
    decision, open question Q3.
  - Credentials should stay **on the agent**, in a local config or secrets
    file keyed by target name, and never be uploaded. The dashboard
    stores only the target list (name, address, mode). The agent pulls that
    list over the existing outbound connection. **(judgment call, Q4)**
  - The external port scanner's safety check is "only scan an IP that
    connected to us as an agent" (`snapshots.source_ip`). That doesn't hold
    for remote hosts, whose traffic comes from the agent's IP. Remote hosts
    are **not eligible** for external scanning unless verified some other
    way (Q5).

Recommendation: ship the **schema and protocol for many hosts per agent now**
(it is cheap and avoids a second migration). **Implement only `local` mode**
until there is a concrete remote use case and the Q3 security decision is
made.

**As implemented (2026-09-27, migration 0012, PROTOCOL.md §4).** Q3–Q5
were decided (§6) and `ssh` mode is built for Linux. It turned out to need
**no command execution**: every Linux collector reads files, so a remote
target is the same collectors over a read-only SFTP filesystem
(`agent/internal/target/ssh.go`), and the recommended `authorized_keys`
entry forces `sftp-server -R` on the remote side. Walking live process
state (listeners, deleted libraries) is not done remotely and reports
`skipped`; kernel, uptime and arch come from single `/proc` files. The
agent generates its own ed25519 key in its data directory and reports only
the public half. Host keys are pinned after the user confirms the
fingerprint the agent reported. `winrm` stays reserved; Windows and macOS
remote collection would need the fixed read-only commands Q3 allows.

### 4.3 Enrollment and identity

- **Enrollment creates an agent, not a host.** The token → `agents` row +
  `agent_credentials(agent_id)`. The response keeps the same field names
  (`agent_id`, `agent_secret`), so the agent binary needs no change for
  enrollment.
- **Hosts are created or attached on first data.** Each snapshot carries
  a `host` block with identity keys:
  - Linux: `/etc/machine-id` (read via `/host/etc/machine-id`)
  - Windows: `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, SMBIOS UUID
  - macOS: `IOPlatformUUID`

  The server upserts the host by `(user_id, identity kind, value)` and
  creates the `local` assignment. Reinstalling the agent on the same
  machine (lost `credentials.json`, rebuilt container volume) **reattaches
  to the existing host and keeps its history**, where today it creates a
  duplicate host.
- **Cloned VMs share `machine-id`.** It is common on templated VPS images.
  Mitigation: if a second *agent* claims an identity that already has an
  active local agent, create a new host and flag "possible duplicate
  identity" instead of merging silently. Provide merge and split actions in
  host management later (Q12).
- **Remote hosts** are created up front in the dashboard (name, address,
  mode, assigned agent). Their identity keys are filled from their first
  successful collection.
- **Credential rotation and revocation** move to the agent level
  (`agents.revoked_at`, `agent_credentials.rotated_at`). This lines up with
  the existing task items ([tasks/cross-cutting-gaps.md](tasks/cross-cutting-gaps.md)).

**As implemented (P1.5, migration 0008, `server/internal/store/agents.go`).**

- `POST /v1/enroll` creates `agents` + `agent_credentials` in one
  transaction with the token delete (`EnrollAgent`). Name: the token's
  `agent_name`, else the enrolling hostname. `version`/`platform` are
  stored when sent. No host is created.
- Ingest authenticates `X-Agent-ID` against `agent_credentials`
  (revoked → 401), then `resolveHost` maps the push to a host inside the
  snapshot transaction. The agent row is locked `FOR UPDATE` (one agent's
  pushes resolve one at a time), and the identity is serialised with a
  transaction advisory lock on (user, kind, value), so two agents
  claiming one machine-id at once resolve in turn.
- Rules (PROTOCOL.md "Host resolution"): an agent's local assignment is
  **sticky**; a first push re-attaches by identity only when no *other
  active* agent collects that host locally, otherwise it creates a new
  host flagged `hosts.duplicate_of` (Q12); with no identity, the first
  push creates a host for the agent and every later push reuses it.
- **Active** = `revoked_at IS NULL` and `last_seen_at` within
  `max(3 × push interval, 2 min)`; the interval is the agent's reported
  `agent.interval_seconds` (`agents.push_interval_seconds`), else 15 min.
  So a reinstall re-attaches once the old agent is revoked or has been
  silent for three intervals. A reinstall *faster* than that (container
  recreated with a lost volume and pushing again within 45 min at the
  default interval) is indistinguishable from a clone on its first push,
  and gets a flagged duplicate host; merge (below) is the fix.
- Identity kinds are the payload's `host.identity` keys (`machine_id`;
  later `machine_guid`, `smbios_uuid`, `platform_uuid`) rather than the
  `linux-machine-id` style sketched in §4.6. Values are lowercased.
- A machine-id that shows up later for a host (older agent upgraded, or
  a host created without one) is attached to that host if unclaimed.
- Remote hosts created in the dashboard: built in migration 0012 (§4.2
  "As implemented", PROTOCOL.md §4). The host and its `ssh` assignment
  (`target_ref` = the host id) exist before the first push; its identity
  and hostname fill in from that push.

**Management (migration 0011, `web/src/app/dashboard/manage-actions.ts`).**
Every dashboard mutation on these Go-owned tables is a server action that
calls one `mgmt_*` SQL function with the session user's id; the function
scopes every row it touches by that id and returns a status (`ok`,
`not_found` for another user's row as for a missing one, or a reason).
The Go integration tests (`store/mgmt_integration_test.go`) call the same
functions, cross-tenant cases included.

- **Revoke agent** (`agents.revoked_at`): irreversible; ingest and
  rotation return 401. Hosts and history are kept; a new agent on the same
  machine re-attaches (the revoked agent is not active).
- **Rotate credentials**: sets `agent_credentials.rotate_requested_at`;
  the agent rotates itself on its next push (PROTOCOL.md §3). Grace window
  for the previous secret: 1h or until the new one is first used.
- **Rename host**: `hosts.label` (display name); `hostname` stays what the
  agent reports.
- **Archive / unarchive** (`hosts.archived_at`): hidden from the Hosts
  list (State facet), the overview and the fleet vulnerability/package
  views (`h.archived_at IS NULL` in every fleet query). Snapshots,
  inventory and findings are kept as they are: findings are not resolved
  (they weren't fixed), they are just out of fleet views, and archived
  hosts don't alert (no finding events; left out of agent events'
  `host_ids`, `store/alerting.go`). Pushes from an
  agent that still collects an archived host are recorded but don't
  unarchive it (revoke the agent to stop them); a *new* agent that
  re-attaches to it by identity does unarchive it. The per-host pages stay
  reachable.
- **Delete host**: hard delete with a typed hostname confirmation
  (checked in the function too), cascading to snapshots, inventory,
  findings, identities and assignments. Agents are kept. If an active
  agent still reports the host, its next push re-creates it; the dialog
  says to revoke first.
- **Merge a flagged duplicate into its original** (`mgmt_merge_host`,
  only when `duplicate_of` = that original, neither archived): the
  duplicate's assignments move to the original (an agent that already
  collects the original just drops its duplicate assignment), its
  identities move, hosts flagged against it are re-pointed, and the
  duplicate is archived with `merged_into`. Its snapshots, `host_software`
  ranges and findings are **not moved**: splicing two overlapping range
  sets and colliding findings (`UNIQUE (host_id, dedup_key)`) is where
  corruption would come from, and a duplicate from a fast reinstall has
  minutes of history. The moved agent's next push diffs against the
  original's inventory state, so the original's ranges simply continue
  (tested). Agent rows are locked first, as in ingest, so an in-flight
  push finishes before the merge or resolves after it. Merged hosts stay
  archived.
- **Not a duplicate** (`mgmt_dismiss_duplicate`): clears `duplicate_of`
  and records `duplicate_dismissed_of`, so ingest doesn't flag the host
  against the same host again (it still could against a different one).
- **Detach** (`agent_hosts` row delete): only for an agent that isn't
  active (revoked or silent past the active window;
  `mgmt_agent_active` mirrors `store.activeAgentSQL`, with a test that
  they agree). An active agent's next push would just re-attach. Typical
  use: the old agent left on a host after a reinstall was merged.

### 4.4 Wire protocol changes (additive where possible)

```jsonc
// POST /v1/snapshots, schema_version 2 (one request per host collected)
{
  "schema_version": 2,
  "agent": { "version": "0.3.0", "platform": "linux/amd64" },
  "host": {
    "ref": "local",                            // or the remote target name assigned in the dashboard
    "identity": { "machine_id": "…" },         // Linux; Windows: machine_guid, smbios_uuid; macOS: platform_uuid
    "hostname": "web-1",                       // refreshed every push (today only sent at enrollment)
    "os_family": "linux"
  },
  "collected_at": "…",
  "os": { "id": "ubuntu", "version_id": "22.04", "codename": "jammy", "kernel": "6.8.0-45-generic", "build": null },
  "uptime_seconds": 123456,
  "collectors": {                               // per-collector status, so a failed collector is "unknown", not "empty"
    "deb_packages":   { "status": "ok" },
    "tcp_listeners":  { "status": "ok" },
    "systemd_units":  { "status": "error", "error": "…" }
  },
  "packages": [ { "name": "libssl3", "version": "3.0.2-0ubuntu1.15", "arch": "amd64",
                  "source": "openssl", "source_version": "3.0.2-0ubuntu1.15" } ],
  "listening_sockets": [ … ],
  "reboot_required": false,
  "public_ipv4": "…", "public_ipv6": "…"
  // plus OS-specific sections, present only when that collector ran: "services", "windows_updates", ...
}
```

- `source` / `source_version` on packages are **additive and can ship in
  v1 now**. They are the only change Phase 1 matching needs.
- v2 is required only for `host` and `collectors`. A v1 payload is treated
  as `host.ref = "local"` of the authenticating agent. Existing agents keep
  working unchanged after the server-side split (§4.7).
- One request per host, rather than a batched multi-host body, keeps
  request size bounded and failure isolated. **(judgment call)**
- New: `GET /v1/agent/config`. It returns the agent's assigned remote
  targets and the desired interval. The connection is still outbound only.
  It is needed only once remote mode exists.

### 4.5 Schema shape for per-OS data

Options:

| Option | Shape | Pros | Cons |
|---|---|---|---|
| A. One wide table | `snapshots` with every OS's columns, nullable | trivial queries | dozens of mostly-NULL columns; every new fact is a migration; no place for lists |
| B. Per-OS tables | `linux_snapshots`, `windows_snapshots`, `macos_snapshots`, and per-OS lists | precise types | cross-OS views (all services, all software) need UNIONs; triples the code paths even where concepts are shared |
| C. Generic typed inventory | `inventory_items(host_id, kind, key, attrs jsonb, first_seen, removed)` | zero migrations for new facts | weak typing; vuln matching needs indexed typed columns; jsonb query sprawl in the UI |
| **D. Hybrid: common core + per-concept tables + jsonb extras** | see below | shared concepts queried uniformly; strong types where we join/filter; OS-specific long tail doesn't need migrations | still requires deciding which facts are "first-class" |

**Recommendation: D.**

- **Core**:
  - `hosts` has `os_family` plus a normalized current OS summary (`os_id`,
    `os_version`, `os_codename`, `os_build`, `kernel`, `arch`). It is
    updated by ingest from the latest snapshot, so host lists never need a
    LATERAL join. Today's `getHostsForUser` does that join for public IPs.
  - `snapshots` keeps cross-cutting scalars: `collected_at`, `source_ip`,
    public IPs, `uptime_seconds`, `reboot_required`, `package_set_hash`,
    `collector_status jsonb`, `agent_id`.
- **Per-concept tables, shared across OSes where the concept is shared**,
  all using the same **validity-range pattern** as `host_software`:
  - `software_versions` / `host_software` (§2.6). The `ecosystem` column
    covers dpkg, Windows programs, macOS apps and pkg receipts, and
    Homebrew.
  - `host_services`: one table for systemd units, Windows services and
    launchd jobs. Columns: `manager` (`systemd` | `scm` | `launchd`),
    `name`, `display_name`, `start_mode` (`auto` | `manual` | `disabled`),
    `state` (`running` | `stopped` | …), `run_as`, `binary_path`, and
    `attrs jsonb` for manager-specific extras.
  - `host_listeners`: listening sockets, moved from per-snapshot rows to
    ranges. "Port 5432 just became public" then becomes a range opening,
    which the alerting phase needs anyway.
  - `host_os_patches`: Windows KBs/hotfixes (and later macOS rapid security
    responses). Columns: `kind`, `patch_id`, `installed_on`, plus ranges.
  - `host_users`: local accounts, later.
- **Long-tail per-OS scalars go into `snapshots.facts jsonb`.** Examples:
  Windows Defender signature age, BitLocker state, macOS SIP, Gatekeeper,
  FileVault, XProtect version, unattended-upgrades config. Promote a fact to
  a real column or table only when a finding, filter or alert needs it.
  `facts` is validated against a Go struct per OS on ingest, so it isn't a
  free-form dump.

Trade-off accepted: a fact moves between jsonb and a column when it becomes
important. That costs one migration and a backfill from `facts`, which is
cheaper than designing all three OSes' schemas up front.

**As implemented (`migrations/0010_host_facts.up.sql`, P1.5).**
`host_services`, `host_listeners` and `host_users` are validity-range
tables like `host_software`, but not interned: each row carries its
values plus `row_key` (natural key: `systemd/ssh.service`,
`tcp 0.0.0.0:5432`, `alice`) and `row_hash` (hash of all values,
`server/internal/hostfacts`). At most one range per (host, row_key) is
open; any value change (a service stops, a port changes owner, a user
joins `sudo`) closes it and opens a new one at the same boundary, so
history needs no extra table. Bookkeeping is per (host, kind) in
`host_fact_state` (`services:systemd`, `listeners:tcp`, `listeners:udp`,
`users:local`), mirroring `host_inventory_state`: an unchanged set hash
only moves `confirmed_at`; pushes not newer than it are stale; a kind is
diffed only when its collector is `ok`; a truncated list is additive
(opens/replaces, never closes) and leaves `set_hash` NULL. TCP and UDP
share `host_listeners`, partitioned by `transport`, because their
collectors fail independently. The owning pid is not part of a listener
range (it would churn on restarts); `listening_sockets` keeps it per
snapshot. No backfill: ranges start at each host's first push after
0010. `host_users` was cheap enough to land now rather than as a fact.
`snapshots.facts` holds `needs_restart` and `unattended_upgrades`,
validated against `hostfacts.LinuxFacts`; `snapshots.uptime_seconds` and
`snapshots.arch` / `hosts.arch` are columns. The dashboard reads the
open ranges (Services / Listeners / Users host tabs) and the newest
snapshot's facts (Overview), all scoped by `hosts.user_id`.

**Docker (`migrations/0013_docker.up.sql`, P1.6).** Same range pattern,
with two optional column groups in `hostfacts.Table`: *detail* columns
(filled by an inspect; hashed through `detail_hash`) and *live* columns
(stored on the range, updated in place, never in `row_hash`).

- `host_containers` (kind `containers:docker`, `row_key` = container id):
  name, image ref, `image_id`, `state`, compose project/service and Swarm
  stack/service/task pulled out of the labels, `labels`; detail `ports`,
  `networks`, `network_mode`, `privileged`, `restart_policy`, `mounts`;
  live `started_at`, `inspect_error`. A state change opens a new range,
  as for `host_services`; a restart ending in the same state only moves
  `started_at`. A partial entry (inspect failed) takes the previous
  range's `detail_hash`, so it doesn't change the range, and a new range
  it opens (e.g. running → exited) copies the detail and `started_at`
  from the one it replaces. NULL detail = never inspected.
- `host_images` (kind `images:docker`, `row_key` = image id): repo tags
  and digests (hashed), detail `os` / `arch` / `variant`, live
  `inspect_error`. `container_images` holds the content fleet-wide,
  keyed by `(image_id, os, arch, variant)` because containerd-store ids
  are index digests shared across platforms; immutable once written,
  only from full inspects. Join `USING (image_id, os, arch, variant)`.
- `host_docker`: one current row per host: engine version, API version,
  storage driver, image store, rootless, Swarm state / node / cluster /
  role (`engine_collected_at`), and the networks list as jsonb
  (`networks_collected_at`); each part written only from a newer push
  whose collector was ok. Networks aren't ranges: nothing keys off their
  history yet, and exposure needs container ports and network mode.
- `swarm_services` ranges belong to `(user_id, cluster_id)`, not a host,
  with `swarm_clusters` as their bookkeeping (set hash, confirmed_at,
  last manager). Any manager's ok push diffs the whole cluster; workers'
  never do (they aren't told the cluster id). The spec is hashed (an
  image update opens a range); `running_tasks` / `desired_tasks` are live.
  Clusters are per user so one user's agent can't write another's.

Current rows are `removed_at IS NULL`. Why Docker data is missing comes
from the newest snapshot's `collector_status` (`docker_*` reasons,
PROTOCOL.md "Docker sections"); stored rows are left as last known.

**Container image packages (`migrations/0014_image_software.up.sql`,
P2a).** An image's package list is interned into `software_versions`
like a host's (same `internVersions`), so the matcher,
`software_vulnerabilities` and every re-match trigger cover images
unchanged; newly interned or source-upgraded versions enqueue
`match_versions` in the write transaction
(`jobs.EnqueueAfterImageSBOM`). Image content is immutable, so a list is
a plain set, replaced as a whole when re-generated, not ranges.

- `image_sbom_state`: one row per (image key, owner), with a surrogate
  `id`. `owner_user_id` is NULL for lists the server obtained by digest
  (`attestation`, `server-syft`: fleet-wide) and the user for an agent's
  (`agent-syft`: that user's hosts only); a CHECK ties source to owner and
  `UNIQUE NULLS NOT DISTINCT` makes NULL one owner. Status `ok` |
  `unavailable` | `error` with `reason`; tool name/version,
  `generated_at`, `package_count`; the image's os-release (`distro`,
  `distro_version`, `distro_name`) and `release`, the key its distro
  packages were interned under. Bookkeeping: `attempts` (failures since
  the last ok), `last_attempt_at`, `next_attempt_at` (NULL = not on a
  timer). A failure never overwrites an ok list. No row = not attempted.
- `image_software (sbom_id, software_id, paths)`: entries with the same
  interned key are merged, `paths` unioned. Reverse lookup by
  `software_id` for reconciling image findings.
- `image_sbom_effective(user)`: per image key, the server list if ok,
  else the user's agent list if ok (inlined by the planner, so an
  image-key filter is an index scan).
- **purl → key (`server/internal/purl`).** `ecosystem` = purl type
  (explicit table; unknown types are still stored under their type).
  Distro types (`deb`, `apk`, `rpm`, `alpm`) take `distro` = os-release
  `ID` and `release` = `purl.ReleaseFor`: the codename for debian/ubuntu
  (VERSION_CODENAME, else VERSION_ID via `distro_releases`, else `''`,
  never the number), major.minor for alpine (`3.20`), VERSION_ID
  elsewhere; without os-release, the purl's `distro=` qualifier
  (`debian-12`, `3.20.3`, `bookworm`). Version is the purl version with
  an `epoch` qualifier folded in as `N:` (deb/rpm), as dpkg prints and
  hosts store it. Source from the `upstream` qualifier (`name` or
  `name@version`; rpm source rpm file names), else binary name/version
  with `source_inferred`, as host ingest does. Names use OSV's form:
  npm `@scope/name`, PyPI PEP 503 normalised, Go module path, Maven
  `group:artifact`; versions are verbatim (Go keeps its `v`).
- **Findings and scores (migration 0015, §2.6 "Image findings and
  scores").** A host gets `vulnerable_image` findings for an image only
  while a current container on it uses the image; every image gets a
  score (`image_sbom_scores`, `image_scores(user)`). A container or
  image range opening or closing at ingest queues `reconcile_host`.
- **Server lists from registry attestations (`image_sbom` worker,
  `internal/imagesbom`).** Repo digests come from the key's open
  `host_images` rows (any host); each is tried until one yields an SBOM
  (`internal/registry`: BuildKit attestation manifest for the platform,
  else OCI referrers; SPDX preferred over CycloneDX). The key's
  `image_id` must be the index, platform manifest or config digest of
  what the registry serves, else the digest is not used ("registry image
  doesn't match this image"). `internal/sbom` reads the document: tool
  = the scanner, not BuildKit (`docker-scout` for Docker Official
  Images, `syft` elsewhere); `generated_at` = the document's creation
  time; OS from an OPERATING-SYSTEM package / CycloneDX
  `operating-system` component, else the majority of distro purls'
  qualifiers (Scout's `os_name`/`os_version`/`os_distro`, Syft's
  `distro=`); `release` via `purl.ReleaseFor` with `distro_releases`.
  Docker Scout writes no `upstream` qualifier: a binary's source is its
  SPDX `GENERATED_FROM` relationship, folded into `upstream`, and deb
  entries that are only a source package (their dpkg evidence names only
  other packages: `glibc`, `gcc-14`) are dropped. `paths`: Scout's
  "evident-by" files / Syft's `sourceInfo`, only the package database for
  distro packages. Failures on the server row: `unavailable` with
  `store.SBOMReason*` (no attestation, private or local, fetching
  disabled; also too large, mismatch, unreadable) and no timer; `error`
  with `next_attempt_at` (30 min × 2^attempts, capped at 24 h, never
  before a registry's Retry-After).
- **Server lists from pulling the image (`image_scan` worker,
  `internal/imagescan`, source `server-syft`).** For the no-attestation
  work list: `image_sbom` records "registry has no SBOM attestation"
  as a hand-over (`attempts` unchanged, no timer) and queues
  `image_scan`, which pulls the platform's layers by digest, extracts
  them and runs Syft (tool `syft`, Syft's version, `generated_at` = scan
  time). Syft's packages go through the same purl rules (`distro=`,
  `upstream=`, epoch in the deb version) so they intern like attestation
  and host packages; `paths` as above (the package database for distro
  packages); packages Syft reports without a purl (e.g. Windows
  launcher binaries in Python packages) are not stored. Scan failures
  on the server row: `unavailable` over a size cap, unsupported layers
  or the memory limit; `error` with the same backoff on timeout or
  crash (the retry re-checks the attestation first). Neither source
  ever replaces an `ok` list.

### 4.6 Target schema sketch (identity and topology)

```sql
CREATE TABLE agents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            text NOT NULL,             -- defaults to the local hostname
    agent_version   text,
    platform        text,                      -- 'linux/amd64', 'windows/amd64', 'darwin/arm64'
    created_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz,
    revoked_at      timestamptz
);

-- Re-keyed from host_id to agent_id.
CREATE TABLE agent_credentials (
    agent_id        uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    secret_hash     text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    rotated_at      timestamptz
);

ALTER TABLE hosts
    ADD COLUMN os_family      text CHECK (os_family IN ('linux','windows','macos')),  -- NULL until first snapshot
    ADD COLUMN os_id          text,        -- 'ubuntu', 'debian', 'windows', 'macos'
    ADD COLUMN os_version     text,        -- '22.04', '11 24H2', '15.1'
    ADD COLUMN os_codename    text,        -- 'jammy'; NULL elsewhere
    ADD COLUMN os_build       text,        -- Windows '26100.2033' (build.UBR); macOS '24B83'
    ADD COLUMN kernel         text,
    ADD COLUMN arch           text,
    ADD COLUMN current_package_set_hash bytea,
    ADD COLUMN inventory_confirmed_at   timestamptz,
    ADD COLUMN archived_at    timestamptz;

CREATE TABLE host_identities (
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind            text NOT NULL,             -- 'linux-machine-id' | 'windows-machine-guid' | 'smbios-uuid' | 'macos-platform-uuid'
    value           text NOT NULL,
    host_id         uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, kind, value)
);

CREATE TABLE agent_hosts (
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    host_id           uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    mode              text NOT NULL CHECK (mode IN ('local','ssh','winrm')),
    target_ref        text NOT NULL DEFAULT 'local', -- name the agent uses in host.ref; matches its local credential entry
    address           text,                          -- remote only
    enabled           boolean NOT NULL DEFAULT true,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_collected_at timestamptz,
    last_error        text,
    PRIMARY KEY (agent_id, host_id),
    UNIQUE (agent_id, target_ref)
);
CREATE UNIQUE INDEX agent_hosts_one_local_idx ON agent_hosts (agent_id) WHERE mode = 'local';

ALTER TABLE snapshots
    ADD COLUMN agent_id          uuid REFERENCES agents(id) ON DELETE SET NULL,
    ADD COLUMN uptime_seconds    bigint,
    -- package_set_hashes jsonb and collector_status jsonb (nullable) already
    -- exist since P1a (migration 0003); see §2.2 "As implemented".
    ADD COLUMN facts             jsonb NOT NULL DEFAULT '{}';
-- snapshots keeps its os_* columns as the per-push record; hosts.os_* is the current summary.

CREATE TABLE host_services (
    host_id         uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    manager         text NOT NULL,             -- 'systemd' | 'scm' | 'launchd'
    name            text NOT NULL,
    display_name    text,
    start_mode      text,                      -- 'auto' | 'manual' | 'disabled' | 'static' | ...
    state           text,                      -- 'running' | 'stopped' | ...
    run_as          text,
    binary_path     text,
    attrs           jsonb NOT NULL DEFAULT '{}',
    first_seen_at   timestamptz NOT NULL,
    removed_at      timestamptz,               -- a change in start_mode/state closes and reopens the range
    PRIMARY KEY (host_id, manager, name, first_seen_at)
);

CREATE INDEX hosts_user_id_idx ON hosts (user_id);
```

Also on the `enrollment_tokens` side: add an optional `agent_name text`, so
the dashboard can pre-name the agent. The token stays one-time and
1-hour, same as today.

### 4.7 Migration from today's model

Existing rows can be migrated with **no agent-side change**:

1. For every `hosts` row, insert `agents (id = hosts.id, user_id, name = hostname)`.
   **Reusing the id** means every deployed agent's `credentials.json`
   `agent_id` stays valid.
2. Move `agent_credentials.host_id` → `agent_id` (same values).
3. Insert `agent_hosts (agent_id = id, host_id = id, mode = 'local')`.
4. Backfill `snapshots.agent_id = host_id`.
5. Server: `X-Agent-ID` now means `agents.id`. A v1 payload resolves to that
   agent's `local` host.

Old agents keep pushing. The new agent's v2 payload adds `host.identity`,
which fills `host_identities` on the next push.

**As implemented (`migrations/0008_agent_host_split.up.sql`).** Steps
1–4 as above, for every `hosts` row (not only those with a credential),
with `agents.created_at`/`last_seen_at` copied from the host and
`agent_hosts.last_collected_at` = the host's newest snapshot
`received_at`. Also: `hosts.os_family = 'linux'` and the OS summary
(`os_id`, `os_version`, `os_codename`, `kernel`) from each host's newest
snapshot; `enrollment_tokens.agent_name`; `snapshots.uptime_seconds` and
`snapshots.facts` (reserved, not written yet); `hosts.os_build`/`arch`
(not written yet: the agent doesn't report them). No payload `v2` was
needed: the `host` and `agent` blocks were added within
`schema_version: 1` (PROTOCOL.md "Versioning"). The down migration keeps
only credentials whose agent id is also a host id. Verified on the dev
data: all six pre-existing agents kept pushing with their old
`credentials.json` onto their old hosts, with findings intact.

### 4.8 Per-OS collectors: what's worth sampling

"No exec" means pure file, registry, API or `/proc` reads. That is the
preference for `local` mode, in line with the current agent's principle.

**Linux: Debian/Ubuntu first, other distros later (Phase 2 RHEL/Alpine)**

| Fact | Local source (no exec) |
|---|---|
| Packages | `/var/lib/dpkg/status`, adding `Source:`. RPM needs `rpmdb.sqlite`; Alpine reads `/lib/apk/db/installed` (Phase 2). |
| OS, kernel, uptime | `/etc/os-release`; `/proc/sys/kernel/osrelease` (the running kernel; host and container share it); `/proc/uptime` |
| Identity, hostname | `/etc/machine-id`, `/etc/hostname` (instead of `os.Hostname()`) |
| systemd services | Enabled state from unit files and `*.wants/` symlinks under `/etc/systemd/system`, `/lib/systemd/system` and `/usr/lib/systemd/system`. Running state from `/proc/*/cgroup`: `…/system.slice/<unit>.service`. This avoids needing D-Bus / `systemctl`, which would mean mounting the system bus into the container. It is less complete than `systemctl` (no "failed" state), which is acceptable for v1. |
| Pending reboot | Already collected (`/var/run/reboot-required{,.pkgs}`). Add "running kernel ≠ newest installed `linux-image-*`" as a server-side check. |
| Stale processes after upgrade | `/proc/*/maps` entries marked `(deleted)` for `.so` files, which is what needrestart does. README goal 3, "patched but not fixed". |
| Unattended-upgrades | Enabled: `/etc/apt/apt.conf.d/20auto-upgrades` (`APT::Periodic::Unattended-Upgrade "1"`). Last apt update: mtime of `/var/lib/apt/periodic/update-success-stamp`. Last run: tail of `/var/log/unattended-upgrades/unattended-upgrades.log`. |
| Security updates available | **Server-computed** from matches (`fixed_version` exists and is newer than installed). No agent work is needed. Non-security pending upgrades need `/var/lib/apt/lists/*_Packages` parsing, which is heavy (Q13). |
| Listening sockets | Already collected (TCP/TCP6). UDP (`/proc/net/udp{,6}`) is cheap to add. |
| Users | `/etc/passwd` (uid ≥ 1000 plus uid 0, and login shell); `/etc/group` for sudo/admin membership. Never `/etc/shadow`. |
| Ubuntu Pro attachment | `/var/lib/ubuntu-advantage/status.json` |

**As implemented (Linux, P1.5).** Collectors in `agent/internal/collector`
(`uptime.go`, `arch.go`, `ports.go`, `systemd.go`, `procs.go`,
`users.go`, `deletedlibs.go`, `unattended.go`), wired in
`agent/internal/snapshot`, each gated on the detected OS and on the
target's `LiveProc` capability, each with its own status. Differences
from the table above: arch comes from the installed `dpkg` package's
`Architecture` (the userland's native arch), falling back to
`/proc/sys/kernel/arch`; UDP "listeners" are bound, unconnected sockets;
systemd `start_mode` adds `manual` (started by an enabled
socket/timer/path unit) and `static`/`masked`, and running state comes
from `/proc/<pid>/cgroup` matched on the `system.slice` segment (the
agent sits in its own cgroup namespace); needs-restart also names the
systemd unit to restart and counts processes it couldn't read (no
`CAP_SYS_PTRACE`); the last unattended run is its periodic stamp, not
the log. Wire details in PROTOCOL.md "Linux breadth sections".

**Windows (requires a native Windows agent: a Windows service, not Docker)**

| Fact | Source |
|---|---|
| OS version and patch level | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`: `ProductName`, `DisplayVersion`, `CurrentBuild`, **`UBR`**. `CurrentBuild.UBR` is the real cumulative-update level and the best key for vuln matching. |
| Identity | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`; SMBIOS UUID via WMI `Win32_ComputerSystemProduct` |
| Installed programs | Uninstall keys: `HKLM\…\CurrentVersion\Uninstall`, `HKLM\…\WOW6432Node\…\Uninstall`, and per-user `HKU\<sid>\…\Uninstall`. `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`. Plus Appx/MSIX packages later. |
| Hotfixes / KBs | WMI `Win32_QuickFixEngineering`. This is incomplete for modern cumulative updates, so treat the build and UBR as primary. |
| Windows Update state | Windows Update Agent COM API (`IUpdateSearcher`) for pending updates. It can be slow, so run it on a longer cadence. Last successful install/scan comes from the WU registry and event log. Policy (auto-update, WSUS) comes from `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`. |
| Pending reboot | Registry keys: `…\Component Based Servicing\RebootPending`, `…\WindowsUpdate\Auto Update\RebootRequired`, `Session Manager\PendingFileRenameOperations` |
| Services | Service Control Manager via `golang.org/x/sys/windows/svc/mgr`: name, display name, start type, state, account, image path (`services.msc` equivalent) |
| Listening sockets | `GetExtendedTcpTable` / `GetExtendedUdpTable` (iphlpapi), with owning PID |
| Security posture | Defender (`MSFT_MpComputerStatus`: real-time protection on, signature age), firewall profiles enabled, BitLocker status (`Win32_EncryptableVolume`) |
| Users | Local accounts and members of the Administrators group (NetUserEnum / NetLocalGroupGetMembers) |
| Vuln data | Separate problem: MSRC CVRF API (CVE → product → KB/build). Third-party programs have no good free feed (NVD CPE matching is noisy). Q14. |

**macOS (requires a native agent: a launchd daemon, signed and notarized
pkg, not Docker, since Docker on macOS runs in a Linux VM and can't see
the host)**

| Fact | Source |
|---|---|
| OS version | `/System/Library/CoreServices/SystemVersion.plist` (`ProductVersion`, `ProductBuildVersion`). Rapid Security Response suffix via `ProductVersionExtra`. |
| Identity | `IOPlatformUUID` (IOKit `IOPlatformExpertDevice`) |
| Installed apps | `Info.plist` of `/Applications/*.app` and `/Applications/Utilities/*.app` (`CFBundleIdentifier`, `CFBundleShortVersionString`). This is fast. `system_profiler SPApplicationsDataType` is complete but slow and an exec. |
| Installer receipts | `/var/db/receipts/*.plist` (what `pkgutil --pkgs` reads): package id, version, install date |
| Homebrew | Directory listing of `/opt/homebrew/Cellar/*/*` (Apple Silicon) and `/usr/local/Cellar/*/*` (Intel), plus `INSTALL_RECEIPT.json`. This avoids running `brew` as the owning user. Casks are under `Caskroom/`. |
| Services | launchd plists in `/Library/LaunchDaemons`, `/Library/LaunchAgents` and `/System/Library/LaunchDaemons` (label, program, `RunAtLoad`, `KeepAlive`, disabled overrides). Running state needs `launchctl print`, an exec, or process-list correlation. |
| Pending updates | `/Library/Preferences/com.apple.SoftwareUpdate.plist` (`RecommendedUpdates`, `LastSuccessfulDate`, `LastRecommendedUpdatesAvailable`). `softwareupdate --list` is authoritative but slow and hits the network. |
| Auto-update settings | Same plist (`AutomaticCheckEnabled`, `AutomaticDownload`, `CriticalUpdateInstall`, `ConfigDataInstall`), plus `/Library/Preferences/com.apple.commerce.plist` (`AutoUpdate`) |
| Built-in protection | XProtect version (`/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist`); SIP (`csrutil status`, exec) and Gatekeeper (`spctl --status`, exec); FileVault (`fdesetup status`, exec); Application Firewall (`/Library/Preferences/com.apple.alf.plist` `globalstate`, or `socketfilterfw --getglobalstate` on newer releases) |
| Listening sockets | No `/proc`. Use `sysctl net.inet.tcp.pcblist_n` (what `netstat` uses), or `lsof -iTCP -sTCP:LISTEN -nP` (exec). |
| Uptime | `sysctl kern.boottime` |
| Users | `/var/db/dslocal/nodes/Default/users/*.plist` (needs root) or `dscl . list /Users` (exec) |
| Vuln data | Apple security releases map macOS version → CVEs, which lets us flag "OS below latest security release". Homebrew packages can be matched loosely via upstream versions; OSV has no Homebrew ecosystem. Q14. |

Several useful macOS facts are only reachable by exec (`csrutil`, `spctl`,
`fdesetup`, `launchctl`). For a native local agent those are fixed,
compiled-in, read-only commands. That is the same carve-out remote mode
needs (Q3).

---

## 5. Support matrix

Legend:

- ✅ **supported now**, verified in code at `agent/internal/collector/*`
  and stored by `server/internal/store/snapshots.go`
- 🛠 planned, with phase
- ❌ not planned
- ❓ TBD, see open questions

Phase labels, as used in [tasks/](tasks/README.md):

- **P1**: Phase 1 remainder (inventory history, matching, packages UI)
- **P1.5**: agent/host split + Linux collector breadth
- **P1.6**: Docker inventory (containers, images, Swarm) + host-side port exposure
- **P2a**: container image packages + vulnerabilities ([decisions/container-image-vulnerabilities.md](decisions/container-image-vulnerabilities.md))
- **P2**: existing Phase 2+ (external scanner, RHEL/Alpine host collectors)
- **P3**: Windows agent
- **P4**: macOS agent

Windows and macOS are **currently non-goals** in README/[tasks](tasks/non-goals.md). Their 🛠
cells assume Q1 is answered yes.

| Data point / collector | Windows | Ubuntu / Debian | macOS |
|---|---|---|---|
| **Agent runtime** (native binary on that OS) | 🛠 P3 (Windows service) | ✅ Docker (`agent/Dockerfile`); plain systemd unit is documented but not shipped | 🛠 P4 (launchd daemon, signed pkg) |
| OS name / version | 🛠 P3 (registry) | ✅ `/etc/os-release`: id, version_id, codename | 🛠 P4 (SystemVersion.plist) |
| OS build / patch level | 🛠 P3 (build.UBR) | ❌ n/a (packages carry it) | 🛠 P4 (build, RSR) |
| Running kernel | ❌ n/a | 🛠 P1.5 (`/proc/sys/kernel/osrelease`) | 🛠 P4 (Darwin version) |
| Hostname | 🛠 P3 | ✅ at enrollment only; 🛠 P1.5 every push | 🛠 P4 |
| Stable machine identity | 🛠 P3 (MachineGuid) | 🛠 P1.5 (`/etc/machine-id`) | 🛠 P4 (IOPlatformUUID) |
| Uptime / boot time | 🛠 P3 | ✅ `/proc/uptime` | 🛠 P4 |
| Listening TCP sockets + owning process | 🛠 P3 (iphlpapi) | ✅ `/proc/net/tcp{,6}` + pid/comm | 🛠 P4 |
| Listening UDP sockets | 🛠 P3 | ✅ `/proc/net/udp{,6}` (bound, unconnected) | 🛠 P4 |
| Agent-reported public IPv4/IPv6 | 🛠 P3 (collector code is portable) | ✅ ipify | 🛠 P4 |
| Server-observed source IP | 🛠 P3 (free once an agent exists) | ✅ `snapshots.source_ip` | 🛠 P4 |
| Host-side port exposure (listeners × firewall × Docker ports) | ❓ | 🛠 P1.6 | ❓ |
| External port-exposure scan | ❓ Q5 | 🛠 P2 (deferred 2026-09-27; `local` hosts only) | ❓ Q5 |
| Installed OS packages | 🛠 P3 (Uninstall registry programs) | ✅ dpkg name/version/arch | 🛠 P4 (.app bundles + pkgutil receipts) |
| Source package name/version | ❌ n/a | 🛠 P1 (dpkg `Source:`) | ❌ n/a |
| Third-party package managers | ❓ (winget/Chocolatey/Scoop) | ❌ (snap/flatpak ❓ later) | 🛠 P4 (Homebrew Cellar/Caskroom) |
| OS patches / hotfixes | 🛠 P3 (KBs via QFE) | ❌ n/a (packages) | 🛠 P4 (RSR via version) |
| Package inventory history | 🛠 P3 (same `host_software` model) | 🛠 P1 (ranges; today: full copy per snapshot) | 🛠 P4 |
| Vulnerability matching | ❓ Q14 (MSRC CVRF by build) | 🛠 P1 (OSV Debian/Ubuntu + KEV/EPSS) | ❓ Q14 (Apple security releases by OS version) |
| Security updates available | 🛠 P3 (WU Agent API) | 🛠 P1 (server-computed from matches) | 🛠 P4 (SoftwareUpdate plist) |
| All pending updates (non-security) | 🛠 P3 (same API) | ❓ Q13 (apt lists parsing) | 🛠 P4 (same plist) |
| Auto-update configured / last run | 🛠 P3 (WU policy + last success) | ✅ unattended-upgrades config, apt stamps | 🛠 P4 (SoftwareUpdate prefs) |
| Pending reboot | 🛠 P3 (CBS/WU/PendingFileRename keys) | ✅ `/var/run/reboot-required{,.pkgs}` | ❓ (no clean equivalent) |
| Processes using deleted libraries | ❌ | ✅ `/proc/*/maps` | ❌ |
| Services inventory + state | 🛠 P3 (SCM) | ✅ systemd unit files + `/proc` cgroups | 🛠 P4 (launchd plists) |
| Local users / admins | 🛠 P3 | ✅ `/etc/passwd`, `/etc/group` | 🛠 P4 |
| Firewall enabled | 🛠 P3 (profiles) | 🛠 P1.6 (ufw config files, Docker `daemon.json`; nftables/firewalld reported as unknown) | 🛠 P4 (ALF) |
| Docker containers, images, networks, Swarm services | ❓ | 🛠 P1.6 (Engine API over an opt-in socket mount, Q17) | ❓ |
| Built-in AV / malware protection | 🛠 P3 (Defender status) | ❌ | 🛠 P4 (XProtect version) |
| Disk encryption | 🛠 P3 (BitLocker) | ❓ (LUKS detection) | 🛠 P4 (FileVault, exec) |
| Platform integrity (SIP/Gatekeeper) | ❌ n/a | ❌ n/a | 🛠 P4 (exec, Q3) |
| Container image packages + vulns | ❌ | 🛠 P2a (registry SBOM / server-side Syft; agent for local and private images) | ❌ |
| Remote (agentless-from-target) collection | ❓ Q3 (WinRM) | ❓ Q3 (SSH) | ❓ Q3 (SSH) |

Verified "✅ now" set, exactly: dpkg packages (name, version, arch), OS
release (id, version_id, codename), TCP/TCP6 listeners with pid and process
name, reboot-required flag and packages, agent-reported public IPv4/IPv6,
server-observed source IP, hostname (enrollment only). All of these are
Linux/Debian-family only. Nothing else is collected today.

---

## 6. Open questions

1. **Windows/macOS scope.** README and [tasks](tasks/non-goals.md) list "Windows/macOS support" as
   an explicit non-goal. This design treats them as future P3/P4. Confirm
   the scope change, and which OS comes first. The recommendation is
   Windows before macOS: more servers, a clearer vuln story via MSRC. Or
   keep both deferred and do only the schema groundwork?
2. **Resolved: OSV bulk** (one parser, both distros, unfixed CVEs via
   DEBIAN-CVE and UBUNTU-CVE records), read from the top-level `Debian/`
   and `Ubuntu/` directories because the per-release zips are stale since
   2024-10 (§2.3). The normalized schema still allows a raw Debian
   Security Tracker / Ubuntu OVAL importer later.
3. **Remote collection and exec.** Remote mode (SSH/WinRM) and several
   macOS facts need running fixed, read-only commands. Is the principle
   "the agent never executes commands" negotiable, restated as "the server
   can never cause execution; the agent runs only compiled-in read-only
   probes"? If not, remote mode is out, and macOS loses
   SIP/Gatekeeper/FileVault.
   **Resolved (2026-09-27, user):** yes, fixed read-only commands compiled
   into the agent are allowed; the server can never cause execution.
   Linux remote collection ended up needing none (read-only SFTP, §4.2
   "As implemented"); the allowance is for Windows/macOS later.
4. **Where remote-target credentials live.** Recommended: only on the agent
   (local config), with the dashboard holding just the target list.
   Alternative: encrypted in Postgres and pushed to the agent. That is more
   convenient, but the platform then holds SSH keys to customer machines.
   **Resolved (2026-09-27, user):** private keys stay on the agent. It
   generates an ed25519 key in its data directory (a persistent volume,
   also holding `credentials.json`), or uses one the operator mounts
   (`SW_SSH_KEY_FILE`); the server stores only the public key and the
   confirmed host keys. Reinstalling with a lost volume means adding the
   new public key on the remote hosts. A "replace agent" flow (the new
   agent takes over the old one's remote hosts) is a follow-up in [tasks/phase-1-5-agent-host-split.md](tasks/phase-1-5-agent-host-split.md).
5. **External port scanning for remote hosts.** Today's safety check
   (`source_ip` equals the agent's connection) can't verify a remote host's
   address. Should remote hosts simply be ineligible, or verified another
   way, for example the user proving control with a DNS TXT record?
   **Resolved (2026-09-27, by recommendation):** ineligible. A remote
   host's pushes carry the agent's `source_ip`; the scanner must only
   consider `local` assignments. **Update 2026-09-27:** the external
   scanner itself is deferred to Phase 2+ in favour of host-side exposure
   analysis ([decisions/port-exposure.md](decisions/port-exposure.md)); this answer applies if it is
   built.
6. **Resolved: `snapshot_packages` is retired entirely** (the alternative
   was keeping raw per-snapshot package rows for N days). Nothing read it beyond the one-off 0003 backfill, and
   `host_software` ranges plus `snapshots.package_set_hashes` cover the
   audit need. Ingest no longer writes it; migration
   `0004_drop_snapshot_packages` drops the table.
7. **Resolved: running kernel for findings, installed kernels as info.**
   The agent reports `os.kernel` (`/proc/sys/kernel/osrelease`); findings
   are raised only for kernel image/module packages of that release;
   other installed kernels are listed by the `host_kernel_packages` view
   with their match counts. While the running kernel is unknown (older
   agents), all installed kernels raise findings, flagged
   `running_kernel_unknown` (§2.5 "As built").
8. **SQL-side version ordering.** Is a Go-computed `version_sort_key` worth
   adding in P1 for fleet "below version X" filters, or is it deferred until
   a page needs it? The alternative, a custom Postgres image with the
   `debversion` extension, is not recommended.
9. **Resolved: import and match ESM (`channel = 'ubuntu-pro'`), label,
   never hide.** A finding whose only fix is in Pro has
   `fix_channel = 'ubuntu-pro'` / `requires_pro = true`; a standard-channel
   fix wins when one exists. Reporting Pro attachment from the agent is
   not needed for the label and is left for later (an attached host's
   installed `+esm` build already clears the match).
10. **Resolved: River** (Postgres-backed, v0.47, tables vendored as
    migration 0006), in a separate `cmd/worker` process; the API holds an
    insert-only client and enqueues with `InsertTx`.
11. **Resolved: shadcn data table (TanStack) as the standard; server-driven
    mode for large tables.** `@tanstack/react-table` v9 behind a reusable
    `DataTable` (`web/src/components/data-table/`): column defs, sorting,
    faceted + text filtering, column visibility, pagination, expandable
    sub-rows. Small per-user lists (agents) load everything and run
    client-side. Large tables (packages, vulnerabilities) use its server
    mode: manual sorting / filtering / pagination, state in the same URL
    search params as before (`url-params.ts` / `url-state.ts`), one page of
    rows queried in SQL. The FilterBar tables migrate to it later.
12. **Resolved by recommendation (P1.5): host identity collisions**
    (cloned VMs with the same `machine-id`). Never auto-merge when a
    different *active* agent already collects the identity's host locally;
    create a separate host with `hosts.duplicate_of` set. The hostname is
    not part of the identity. "Active" and the reinstall trade-off are in
    §4.3 "As implemented". The dashboard resolves a flag with "Merge into
    …" or "Not a duplicate" (§4.3 "Management").
13. **Non-security pending upgrades on Debian/Ubuntu.** Is it worth parsing
    `/var/lib/apt/lists` (large) to show "N updates pending", or is
    "security fixes available" (server-computed, free) enough?
14. **Vuln matching on Windows/macOS.** Do we match OS-level only (MSRC by
    build.UBR, Apple security releases by version), which is feasible and
    fairly accurate, or also attempt third-party apps (NVD CPE, noisy)?
15. **Agent naming in the UI.** After the split, "Agents" is the collector
    list and "Hosts" is the machine list. Should the existing "Register
    agent" button live on Hosts ("Add host" → enroll an agent on it) or on
    Agents? Recommended: both entry points, one dialog. **Resolved by
    recommendation:** the sidebar has Hosts (machines) and Agents
    (collectors); "Add host" on Hosts and "Register agent" on Agents open
    the same enrollment dialog. **Revised 2026-09-27:** "Add host" now
    asks first: "Install the agent on it" (the same enrollment panel as
    "Register agent") or "Reach it from an existing agent" (remote host
    over SSH: pick the agent, enter the address, authorize the agent's key
    on the host, confirm the host key fingerprint).
16. **Multiple agents per host.** The schema allows it (for redundancy or
    migration). Should the UI allow it, or enforce one active collector per
    host? As built, it is allowed and shown (the Hosts list lists every
    collecting agent): after a merge the old and new agent both collect
    the host until the old one is detached or revoked. Enforcing one
    active collector is still open.
17. **Resolved (2026-09-27, user + recommendation): how the agent collects
    Docker.** Engine API, not Docker's on-disk files, because Swarm
    service specs and containerd-store image metadata aren't readable
    from disk and the API also covers rootless Docker and Podman. The
    socket is mounted into the agent (opt-in); the boundary is its code
    (Docker's Go SDK behind an interface with a fixed list of reads,
    since 2026-09-28) and wire types that never carry env / command
    lines. Only hosts with their own agent; remote (SSH) hosts are
    `skipped`. A proxy sidecar was rejected: it ships
    from the same release pipeline, so it doesn't stop the realistic
    threat (a malicious release). Images are collected from the start (image ID, repo
    digests, layer diff IDs) for Phase 2 image CVE matching. Docker and
    Swarm are supported generically, not per platform. Details:
    [decisions/docker-collection.md](decisions/docker-collection.md), [tasks/phase-1-6-docker-exposure.md](tasks/phase-1-6-docker-exposure.md).

---

## 7. Suggested sequencing

1. **P1a, inventory foundation.**
   - Agent: add `source` / `source_version`, and fix the `installed` status
     check. Both are additive, v1.
   - Server: `software_versions` + `host_software` ranges + set-hash
     short-circuit, and backfill from `snapshot_packages`.
2. **P1b, advisories and matching.**
   - `debversion` package with tests
   - OSV Debian/Ubuntu sync into `advisories` / `advisory_affected`
   - KEV/EPSS into `cves`
   - matcher → `software_vulnerabilities`, then findings reconciliation, all
     on a Postgres job queue
3. **P1c, packages UI.**
   - host detail shell; Packages, Vulnerabilities and History tabs
   - fleet `/dashboard/vulnerabilities` and `/dashboard/packages`
   - Overview cards
4. **P1.5, agent/host split.**
   - migration §4.7, v2 payload with `host` + `collectors`
   - identity-based host upsert, nav rename (Hosts vs Agents)
   - Linux breadth: kernel, uptime, machine-id, systemd services, users,
     deleted libraries, unattended-upgrades
5. **P3/P4, Windows then macOS agents**, if Q1 is yes.

P1a–c do not depend on P1.5. The split can land before or after them,
because the new tables key on `host_id`, which survives the split
unchanged.
