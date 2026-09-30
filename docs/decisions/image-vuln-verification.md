# Image vulnerability results checked against Trivy and Grype

Checked 2026-09-29/30 (Phase 2a "Verification"): our package lists and
vulnerabilities for five images, next to Syft, Trivy and Grype on the
same image content. **Result: package lists are identical to Syft's and
Trivy's (after two parser fixes), and the vulnerability sets agree except
for differences in advisory data, all explained below. No version
comparison bugs. The big visible difference is severity: most Debian
issues and Go standard library issues are "unknown" for us and
high/medium for Trivy and Grype, because we don't rank by CVSS.** That,
and third-party packages matched against Debian's advisories, are open
questions (end of the note).

## Setup

One platform, **linux/arm64**, pinned by digest (index, arm64 manifest,
config = our image id):

| Image | Index digest | arm64 manifest | Config (image id) |
|---|---|---|---|
| `postgres:17` | `sha256:d74eeac9a635…c46f` | `sha256:86fa57b44a1d…1761` | `sha256:97432f980da1…4d9c` |
| `nginx:1.27` | `sha256:6784fb0834aa…f7d` | `sha256:e6017bb25206…b103` | `sha256:7791402a0bf5…e7e4` |
| `postgres:17-alpine` | `sha256:b0f9560a2de0…2b24` | `sha256:0b2882c46a2b…6cfa` | `sha256:25a89970a832…5c62` |
| `debian:buster` | `sha256:58ce6f1271ae…a225` | `sha256:fba020fe61e2…191f` | `sha256:ba58cfa2eb92…4125` |
| `node:22-bookworm-slim` | `sha256:43ac6c60b8f8…772c` | `sha256:a0ddbc73510e…3f3e` | `sha256:78175922b173…ae94` |

Full digests: `d74eeac9a635390a49bc21bd49fccd973de707e2a53a76ac49b552b8712ec46f`,
`6784fb0834aa7dbbe12e3d7471e69c290df3e6ba810dc38b34ae33d3c1c05f7d`,
`b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24`,
`58ce6f1271ae1c8a2006ff7d3e54e9874d839f573d8009c20154ad0f2fb0a225`,
`43ac6c60b8f89723f746e8a92ce91abd5017e627ce1ddfe4238355d3a30b772c` (indexes).

**Ours**: the real pipeline on a copy of dev data (`worker image-sbom`,
`worker image-scan` for buster, `worker match`, which also scores).
Lists: postgres:17, nginx:1.27, postgres:17-alpine and node:22 from
the registry's SBOM attestation (Docker Scout 1.18.1 generated it);
debian:buster has none, so server-side Syft (v1.52.0). Feeds, synced
just before the comparison: OSV Debian to 2026-09-29 23:00 UTC, Alpine
08:30 (no newer export), npm 23:15, PyPI 18:30, Go 21:30; KEV
2026.09.29; EPSS 2026-09-29.

**Others**: Syft 1.52.0 (`registry:` source); Trivy 0.74.0, DB
2026-09-29 19:09 UTC (`--image-src remote --platform linux/arm64
--list-all-pkgs`, Java DB skipped for disk space; the only jar,
`libintl-0.21.jar` in nginx, has no advisories in Grype either);
Grype 0.119.0, DB v6.1.9 built 2026-09-29 06:32 (data to 00:34), run
over Syft's SBOM. **Docker Scout** (`docker scout cves`, v1.24.0) needs
a Docker login even for public images, so it was not run; its SBOMs are
what we ingest for four of the images.

Scripts: kept in the session scratchpad, not in `dev/` (one-off).

## Packages

| Image | Ours | Syft | Trivy |
|---|---|---|---|
| postgres:17 | 142 deb + 4 Go = 146 | 142 + 4 | 142 + 4 |
| nginx:1.27 | 149 deb + 1 Maven | 149 + 1 | 149 (jar skipped, see above) |
| postgres:17-alpine | 45 apk + 4 Go + 1 binary = 50 (was 61 apk) | 45 + 4 + 1 | 45 + 4 |
| debian:buster | 91 deb | 91 | 91 |
| node:22-bookworm-slim | 88 deb + 187 npm + 1 binary | 88 + 198 npm entries (187 distinct name@version) + 1 | 88 + 198 (187 distinct) |

Name and version sets are equal package for package (npm: we store one
row per name@version with every path; Syft/Trivy list each copy).
"binary" is Syft's binary classifier (`node` 22.23.3, `postgresql`
17.11): listed by us as not assessed; Grype also finds nothing for
them, Trivy doesn't detect them.

Two differences were **our bugs, fixed** (`internal/sbom/spdx.go`, tests
in `sbom_test.go`):

- **Alpine origins listed as packages.** Scout's SPDX has an entry for
  each apk *origin* (`openssl`, `krb5`, `alpine-base`…) that binaries
  are `GENERATED_FROM`, installed or not; we kept them all, so
  postgres:17-alpine had 61 apk packages instead of 45 (alpine:latest
  20 instead of 16, postgres:18.6-alpine 77 instead of 58). Now an
  origin whose `CONTAINS` files are all its binaries' files is dropped;
  an installed origin (`alpine-baselayout`, `busybox`, `musl`) has files
  of its own and stays. The deb rule (dpkg evidence) was already right.
- **Nested Go module paths.** Scout writes `github.com/moby/sys/user`
  (in gosu) as `pkg:golang/github.com/moby/sys@0.1.0#user`; we interned
  it as module `github.com/moby/sys`, which doesn't exist, so its
  advisories could never match. When the SPDX package name is
  namespace/name/subpath, the subpath is now part of the module path.

## Vulnerabilities, OS packages

Distinct vulnerability ids per image (a CVE, or a DSA/TEMP/DLA id where
that is the record), and per severity as each tool labels it. Our
labels are our buckets (`internal/severity`); Trivy's are its
vendor-preferred severity; Grype's are its own.

| Image | Ours | Trivy | Grype |
|---|---|---|---|
| postgres:17 (trixie) | **115**: negligible 40, unknown 75 | **119**: critical 1, high 16, medium 34, low 52, unknown 16 | **100**: critical 1, high 20, medium 30, low 9, negligible 40 |
| nginx:1.27 (bookworm) | **414**: critical 2, medium 36, unknown 299, low 1, negligible 76 | **432**: critical 10, high 94, medium 171, low 126, unknown 31 | **402**: critical 25, high 142, medium 133, low 21, negligible 77, unknown 4 |
| postgres:17-alpine (3.24) | **0** | **0** | **2**: high 1, medium 1 |
| debian:buster (10, EOL) | **not assessed** (91 of 91 packages) | **38**: critical 2, high 13, medium 12, low 11 | **80**: high 15, medium 14, low 9, negligible 41, unknown 1 |
| node:22-bookworm-slim | **99**: medium 2, unknown 68, low 1, negligible 28 | **104**: critical 4, high 14, medium 44, low 39, unknown 3 | **97**: critical 6, high 20, medium 33, low 7, negligible 29, unknown 2 |

Overlap: postgres:17 113 ids common with Trivy (ours only 2, Trivy
only 6), 100 with Grype (Grype only 0); nginx 408 with Trivy (6 / 24),
402 with Grype (Grype only 0); node 98 with Trivy (1 / 6), 97 with
Grype (Grype only 0). **Fix states agree exactly**: on nginx we have
167 fixable ids: the 166 common ids Trivy calls `fixed`, plus
CVE-2025-7425, which Trivy lists as `DSA-5990-1` (fixed, same version);
Grype has 165 of them `fixed` and lacks the other two (CVE-2025-7425,
`DSA-5979-2`). Nothing Trivy or Grype calls fixed is unfixed for us.
postgres:17 has no fixable issue in any tool; node has one only in
Trivy, the CVE-less `DLA-4792-1` (tzdata, see 4). Our image scores also count the Go/npm findings
(postgres:17 scores 161 = 115 OS + 46 Go; node 112 = 99 + 13).

### Every difference, by category

1. **Severity source (the bulk of the table).** We rank by KEV, EPSS
   and the distro's own priority; CVSS is only a tiebreaker and never
   sets the bucket (`internal/severity`, rule [2]). Debian's OSV export
   carries the tracker's per-release urgency, which is "not yet
   assigned" for most CVEs, often for years (e.g. `aom` CVE-2023-39616,
   2023): 75 of 115 on postgres:17 and 299 of 414 on nginx are
   "unknown" for us. Trivy falls back to NVD/GHSA CVSS (`SeveritySource`
   `nvd` or other vendors), Grype likewise: on nginx, 85 of our
   "unknown" are high or critical in Trivy, 137 in Grype. Where Debian
   did rank, we agree: our 40 (postgres:17) / 76 (nginx) "negligible"
   are Debian "unimportant", which Grype also calls negligible and
   Trivy maps to low. Smaller effects: Trivy uses one Debian severity
   per CVE (e.g. unstable's) where a release has none (libxml2
   CVE-2025-6170: unimportant in unstable, nothing for bookworm, so low
   in Trivy, unknown for us); EPSS lifts some of ours to medium and KEV
   to critical. Not a bug: the documented rule. Whether to fall back to
   CVSS is an open question (below).
2. **Third-party packages with a Debian name.** nginx:1.27's `nginx`
   1.27.5-1~bookworm comes from nginx.org (maintainer "NGINX
   Packaging"), not Debian. Trivy classifies it `third-party` and
   doesn't match it; we (and Grype) match it against Debian's `nginx`
   advisories, whose unfixed ranges cover every version: CVE-2009-4487,
   CVE-2013-0337 and **CVE-2023-44487 (HTTP/2 rapid reset), critical for
   us through KEV**, although nginx fixed it in 1.25.3. Our worst
   finding on this image is a false positive. Open follow-up.
3. **Debian tracker states OSV doesn't carry.** OSV exports a release as
   affected-without-fix whether the tracker says plain unfixed,
   `<no-dsa>`, `<ignored>`, `<postponed>` or "undetermined"; Trivy keeps
   `will_not_fix` / `fix_deferred` apart and Grype `wont-fix`. So "no
   fix yet" for us covers what Trivy calls will_not_fix (19 on nginx)
   and fix_deferred (77). Two ids follow from it: `pam` CVE-2025-8941
   (tracker: "undetermined" in every release) is reported by us and by
   neither tool; `zlib` CVE-2023-45853 in bookworm is `<ignored>`
   ("minizip not built"): Trivy says will_not_fix, Grype drops it, we
   show it (medium, via EPSS). Needs the tracker's own data; follow-up.
4. **Records OSV has and the tools don't, or the reverse.**
   - Tracker `TEMP-…` ids (no CVE yet; 6 on postgres:17, 5 on node,
     20 on nginx, 12 of them on `libheif1` and 2 on `libde265-0`): Trivy only;
     OSV exports CVE records (and DSAs) only.
   - CVE-less `DLA`s (bookworm is in LTS): `DLA-4726-1`
     ca-certificates, `DLA-4783-1` xz, `DLA-4792-1` tzdata: Trivy only;
     osv.dev has no DLA records. Their CVE fixes reach us through the
     `DEBIAN-CVE-…` records.
   - The same fix under a different id: `DSA-5990-1` (Trivy) is
     CVE-2025-7425 for us (its upstream CVE); `DSA-5979-2` (no CVE) is in
     both ours and Trivy's, not Grype's.
   - A stale OSV record: `sqlite3` CVE-2026-39113 is `<not-affected>` in
     the tracker and Debian deleted its OSV source file, but osv.dev
     still serves `DEBIAN-CVE-2026-39113` as unfixed in trixie, so we
     report it (unknown severity) and neither tool does. Upstream data.
   - Alpine: Grype adds 2 (busybox CVE-2025-60876, zlib
     CVE-2026-85091) with fix state unknown: its NVD CPE fallback for
     issues Alpine's secdb doesn't list. Alpine's feed has fixed issues
     only (Phase 2a "Alpine" item), as does Trivy's; we and Trivy report
     0.
5. **Feed freshness.** Our Debian feed (23:00) was newer than Grype's
   DB (00:34 that day) and Trivy's (19:09). CVEs published on
   2026-09-29 afternoon: 13 OpenSSL CVEs and `libpng1.6`
   CVE-2026-46675 are in ours and Trivy's, not Grype's; `expat`
   CVE-2026-102633 (published 17:17) only in ours. The OpenSSL ones are
   13 of the 15 "ours only vs Grype" on postgres:17 (the other two are
   pam and sqlite3, in 3 and 4). A first run with the morning's
   Trivy DB lacked them too.
6. **End-of-life release.** debian:buster: Trivy warns "no longer
   supported" and still reports 38; Grype 80 (41 negligible). We show
   "release out of support, not assessed" for all 91 packages, never
   clean or zero: as designed (migration 0020).
7. **Kernel / `linux-libc-dev`**: none of these images ship kernel
   packages, so no difference to explain here.
8. **Source vs binary matching**: per (binary package, id) pairs agree
   too (postgres:17 325 / Trivy 328 / Grype 281; the gaps are the ids
   above), so matching deb binaries through their source package and
   apk through the origin is right.
9. **Version comparison**: no disagreement on any common id in fixed
   versions or affected/fixed state, for deb, apk, npm or Go.

## Vulnerabilities, language packages

| Image | Packages | Ours | Trivy | Grype |
|---|---|---|---|---|
| postgres:17, postgres:17-alpine (gosu: Go stdlib 1.24.6, x/sys, moby/sys/user) | 4 Go | 46 | 46 | 46 |
| node:22-bookworm-slim (npm's bundled deps) | 187 npm | 13 (high 7, medium 5, low 1) | 13 (same) | 13 (same) |
| nginx:1.27 | 1 jar | 0 | skipped | 0 |

The (package, id) sets are identical for Go and npm (Grype and Trivy
report Go advisories under their CVE ids, we under the CVE alias of the
`GO-…`/GHSA record). npm severities match exactly (GHSA's). Go: 45 of
our 46 are "unknown" because the Go vulnerability database has no
severity (the standard library issues have no GHSA either); Trivy and
Grype use NVD (high 21-23, medium 20-21). Same question as 1.

One display gap: npm has `pacote` twice (19.0.2 and 20.0.1, nested
under `@npmcli/metavuln-calculator`), both affected by CVE-2026-9496.
Both versions are matched, but `image_sbom_vulns` groups per (source
package, vulnerability), so the row shows one installed version (19.0.2).
Trivy and Grype list both. Follow-up.

PyPI: none of these images has Python packages (no PyPI numbers to compare).

## Open questions and follow-ups

- **Severity when the source has none** (decision needed): keep
  "unknown" (current rule: CVSS never sets the bucket), or fall back to
  CVSS/NVD for Debian "not yet assigned" and Go stdlib issues, e.g. as
  a bucket capped at medium, or shown as "unknown (CVSS 7.5)". The
  assumption behind the rule, "untriaged issues are usually days old",
  doesn't hold for Debian, where most CVEs never get an urgency.
  Recommendation: keep the bucket from the distro, but show CVSS next to
  "unknown" and let it order unknowns (it already does, as the
  tiebreaker), so "unknown" isn't read as "harmless".
- Third-party deb packages (nginx.org, and potentially any vendor repo)
  are matched against Debian's advisories: false positives, including
  KEV-critical ones. Needs a way to tell origin: the dpkg Maintainer or
  apt origin (not in Scout's SBOM; in Syft's metadata), or a version
  outside the release's archive versions (OSV lists them).
- Debian tracker sub-states (`<no-dsa>`, `<ignored>`, `<postponed>`,
  undetermined, `<not-affected>`) and TEMP ids aren't in OSV: consider
  the tracker's JSON as a second Debian source.
- Language packages present at several versions show one installed
  version per vulnerability row.
- Lists written before a parser fix keep the old parse (ok lists are
  never refetched): the two fixes above apply to new lists only; a
  parser version that re-fetches (like `matcher.Version` re-scores) would
  cover it.
