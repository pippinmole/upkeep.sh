# Container image vulnerabilities: our own SBOM + matcher, not Docker Scout

Considered (2026-09-28): what Docker Desktop's "Start analysis" does, i.e.
Docker Scout (`docker scout cves`), versus building the same pipeline on
what we already have.

Scout works in two steps: it builds an SBOM from the image's layers (OS
packages and language packages as package URLs, `pkg:deb/debian/apt@3.0.3`),
then sends it to Docker's backend, which matches it against Docker's
advisory database (distro trackers, NVD, GitHub/GitLab, language
ecosystems). **Not used as our engine**: the backend needs each user's
Docker account and plan and isn't a public API to build on; it would send
every user's image contents to Docker; reading a local image goes through
image export, which the agent's Docker interface deliberately excludes;
and its results wouldn't share our findings model (KEV/EPSS ranking, fix
channels, open/resolved/reopened history). Scout (or Trivy/Grype) stays
useful as a reference to check our results against.

**Decided: the same two steps, on our own data.** The product is the
**inventory first, then matching**, exactly as for hosts (list every apt
package, then match): clicking into an image shows *all* of its
packages, vulnerable or not, and vulnerabilities are a join on top.

- **Package lists are interned into `software_versions`**, the table
  host packages use: `ecosystem` from the package URL type (`deb`,
  `apk`, `npm`, `pypi`, `golang`…), `distro` / `release` from the image's
  `os-release` for distro packages, `''` for language packages. An image's
  content never changes, so its inventory is a plain set per image
  (keyed like `container_images`), not validity ranges. The matcher,
  `software_vulnerabilities`, KEV/EPSS/CVSS and re-matching on advisory
  changes then apply unchanged; image findings reuse the same ranking.
- **Matching and scoring always run on the server** (River worker), where
  the advisories, comparators and re-match triggers live. Advisory
  updates re-check every image without the hosts being involved.
- **Package lists come from the server where it can reach the image,
  and from the agent only where it can't.** Server, per digest,
  fleet-wide, cached: (1) the registry's SBOM attestation when the image
  has one (checked 2026-09-28: Docker Official Images carry an SPDX SBOM
  per platform, anonymously fetchable, with `deb` package URLs including
  distro and release); (2) otherwise pull the image by `repo_digests` and
  run **Syft** (Apache-2.0 Go library) on it. Agent: only for images the
  server can't pull, i.e. locally built images (no repo digest) and
  private registries. We don't store users' registry credentials. The
  server tells the agent which image IDs it needs; the agent runs Syft on
  the layers on disk and sends only the package list, never file contents.
- **Advisories: OSV, extended per ecosystem.** OSV already publishes
  Alpine, npm, PyPI, Go, crates.io, Maven… (and GitHub's advisory data).
  Each ecosystem needs its own version comparator (Debian ordering is
  the only one today), so ecosystems are added one at a time; until
  then their packages are listed but marked "not assessed", never "no
  vulnerabilities".
- **No external API keys.** OSV, KEV and EPSS are public downloads
  (unchanged), Syft is local, public registries allow anonymous pulls.
  An optional platform-wide Docker Hub token only raises the anonymous
  pull rate limit.

The "score" shown for an image is the worst severity bucket plus counts
per bucket, with max CVSS and a KEV flag (the existing `severity.Key`
ranking), not a new composite number. Tasks: [Phase 2a —
container image packages + vulnerabilities](../tasks/phase-2a-image-vulns.md).

**Follow-up decisions (2026-09-28, before implementation):**

- **Findings vs score.** An image used by at least one container on a
  host, in any state (an exited container can be started again), gets
  per-host `vulnerable_image` findings and therefore alerts. An image
  present with no container gets a score only: no findings, no alerts.
- **Trust in package lists.** Lists the server obtained itself (registry
  attestation, server-side Syft, both by digest) are shared fleet-wide
  per image key. Lists sent by an agent are stored per (user, image key)
  and used only for that user's hosts, so one user's agent can't clean
  or poison another user's results. A server-obtained list wins over an
  agent one for the same image key. (`container_images` metadata is
  still first-writer-wins across users; noted as a gap.)
- **Alerting.** Image findings use the existing `finding.*` events.
  Alert rules gain a finding-kind filter (`vulnerable_package`,
  `vulnerable_image`), and existing rules default to both. Users tune
  the first-scan burst with the existing min severity, KEV-only and
  digest settings.
- **Which registries the server contacts.** Any registry host named in
  an image's repo digests, anonymously, through `netguard` (public
  addresses only) with timeouts, size caps and per-registry backoff.
  Internal or private registries fail into "private or local image,
  needs the agent". A server setting disables all outbound image
  fetching for air-gapped installs. It is on by default.
- **Agent-side Syft size** is measured in the agent task before choosing
  between full Syft and an OS-package-only catalogue.
