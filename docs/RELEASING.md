# Releasing

Releases publish three images to GitHub Container Registry, all from the
same tagged commit:

- `ghcr.io/pippinmole/upkeep-agent`
- `ghcr.io/pippinmole/upkeep-server` (the `api` and `worker` binaries)
- `ghcr.io/pippinmole/upkeep-web`

Why this is strict: with the Docker socket mounted, the agent is root on
the host, and the realistic way it gets compromised is a bad release
([Docker collection](decisions/docker-collection.md)). So images are
only built in CI, only from a `vX.Y.Z` tag on a commit that is on
`main`, and every published image is signed and carries an SBOM and
build provenance. Users pin an exact version, never `:latest`, so a bad
release doesn't reach hosts on its own.

The pipeline is [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Versions and tags

- Git tag: `vMAJOR.MINOR.PATCH`, or a pre-release such as `v0.2.0-rc.1`.
  The first release is `v0.1.0`.
- Version inside the images: the tag without the `v` (`0.1.0`). It's
  the `VERSION` build arg, baked in with `-X main.version`: the agent
  reports it as `agent.version`, and the server's `api` and `worker` log
  it at startup (`api 0.1.0 listening on :8080`). Builds outside the
  release pipeline report `dev`; release dry runs report
  `0.0.0-dryrun.<sha>`.
- Image tags for a stable release `v0.1.0`: `0.1.0`, `0.1`,
  `sha-<short>` and `latest`. A pre-release `v0.2.0-rc.1` gets only
  `0.2.0-rc.1` and `sha-<short>`; it never moves `0.2` or `latest`.
- The version users get by default is pinned in two places, which must
  agree: `web/src/lib/agent-image.ts` (the dashboard's install command)
  and `agent/docker-compose.example.yml`. `scripts/check-version-pins.sh`
  checks and bumps both, and the release refuses a stable tag that
  doesn't match them.

Self-hosters who mirror the agent image into their own registry set
`SW_AGENT_IMAGE` on the web container (`web/.env.example`); it's read at
runtime, no rebuild needed.

## Cutting a release

1. **Bump the pins** on a branch (skip if they already say the new
   version):

   ```sh
   git switch -c release-0.2.0 origin/main
   scripts/check-version-pins.sh --set 0.2.0
   scripts/check-version-pins.sh 0.2.0      # ok: agent image pins agree with 0.2.0
   (cd web && bun test src/lib/agent-image.test.ts)
   git commit -am "Release 0.2.0: pin the agent image"
   ```

2. **Open a PR and merge it** once CI is green. Don't tag the branch:
   the tag has to point at a commit on `main`.
3. **Tag the merge commit on `main`** and push the tag:

   ```sh
   git switch main && git pull --ff-only
   scripts/check-version-pins.sh 0.2.0
   git tag -a v0.2.0 -m "v0.2.0"
   git push origin v0.2.0
   ```

4. **Watch the run**: `gh run watch` (or the Actions tab). The `guard`
   job fails if the tag isn't `vX.Y.Z[-pre]`, isn't reachable from
   `origin/main`, or doesn't match the pins. If the `release`
   environment requires a reviewer, approve the `publish` jobs there.
5. **Check the result** with the commands in
   [Verifying an image](#verifying-an-image), against the new version.
6. Write the GitHub release notes for the tag (`gh release create v0.2.0
   --verify-tag --generate-notes`), including the three image digests
   from the run summary.

If the guard fails because the pins weren't bumped, delete the tag
(`git push origin :refs/tags/v0.2.0`; the tag ruleset below means only
an admin can), do steps 1 to 3, and tag again.

## Pre-releases: a real-pipeline dry run

`vX.Y.Z-rc.N` tags go through the whole pipeline: the guard, multi-arch
builds, push to GHCR, attestation and signing. Use one to try a pipeline
change or a risky release for real before the stable tag:

```sh
git tag -a v0.2.0-rc.1 -m "v0.2.0-rc.1" && git push origin v0.2.0-rc.1
```

A pre-release only publishes `0.2.0-rc.1` and `sha-<short>`, so nobody
gets it unless they ask for it. The guard only checks that the two pins
agree with each other, not that they equal the pre-release: `main` never
pins a pre-release.

Cheaper checks, without publishing anything:

- **Pull requests** that change `release.yml`, a Dockerfile or
  `scripts/check-version-pins.sh` run the release workflow in dry-run
  mode: the same multi-arch builds with SBOM and provenance, checked in
  a local OCI layout, but no push, no signing and no write permissions.
- **Manual run** (Actions, `release`, "Run workflow"): the same dry run
  on any branch. This only appears once `release.yml` is on `main`.
- **Locally**, e.g. the agent for both platforms (needs a
  `docker-container` buildx builder for the attestations):

  ```sh
  docker buildx create --name upkeep-release --driver docker-container
  docker buildx build --builder upkeep-release \
    --platform linux/amd64,linux/arm64 --build-arg VERSION=0.0.0-test \
    --sbom=true --provenance=mode=max \
    --output type=oci,dest=/tmp/upkeep-agent-oci,tar=false agent
  docker buildx rm upkeep-release
  ```

## Verifying an image

What each release carries, per image:

| Evidence | Made by | Where | Always? |
| --- | --- | --- | --- |
| Signature | cosign keyless (GitHub OIDC), on the pushed digest | the registry, and the public Rekor log | yes |
| SBOM (SPDX) | BuildKit (`sbom: true`) | attestation manifests in the image index | yes |
| SLSA provenance | BuildKit (`provenance: mode=max`) | attestation manifests in the image index | yes |
| GitHub build provenance | `actions/attest-build-provenance` | GitHub's attestation API and the registry | only while the repo is public (see below) |

**Signature** (cosign v3 or later). The certificate identity is the
release workflow at a `v` tag of this repo:

```sh
cosign verify ghcr.io/pippinmole/upkeep-agent:0.1.0 \
  --certificate-identity-regexp '^https://github\.com/pippinmole/upkeep\.sh/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

For one exact tag, use `--certificate-identity
https://github.com/pippinmole/upkeep.sh/.github/workflows/release.yml@refs/tags/v0.1.0`
instead of the regexp. The same works for `upkeep-server` and
`upkeep-web`.

**GitHub attestation** (when available):

```sh
gh attestation verify oci://ghcr.io/pippinmole/upkeep-agent:0.1.0 --owner pippinmole
```

**SBOM and BuildKit provenance**:

```sh
docker buildx imagetools inspect ghcr.io/pippinmole/upkeep-agent:0.1.0 --format '{{json .SBOM}}'
docker buildx imagetools inspect ghcr.io/pippinmole/upkeep-agent:0.1.0 --format '{{json .Provenance}}'
```

**Pin by digest.** A tag can be moved by whoever controls the registry
account; a digest can't. The strongest setup is to verify once, then run
the digest:

```sh
docker buildx imagetools inspect ghcr.io/pippinmole/upkeep-agent:0.1.0 --format '{{.Manifest.Digest}}'
# image: ghcr.io/pippinmole/upkeep-agent:0.1.0@sha256:<digest>
```

### While the repo is private

- **GitHub artifact attestations** only exist for public repositories
  (or on GitHub Enterprise Cloud): "To use artifact attestations in
  private or internal repositories, you must be on a GitHub Enterprise
  Cloud plan" ([actions/attest](https://github.com/actions/attest#readme)).
  The attest step therefore runs only when the repo is public, or when
  the repository variable `GH_ATTESTATIONS` is `true` (for Enterprise
  Cloud). Making the repo public turns it on with no workflow change.
  Until then, the cosign signature and BuildKit's SBOM and provenance are
  the guaranteed path, and `gh attestation verify` has nothing to find.
- **Cosign keyless signing is public.** The signing certificate names
  the repo (`pippinmole/upkeep.sh`), the workflow path, the tag and the
  commit, and it's recorded in the public Rekor transparency log
  ([search.sigstore.dev](https://search.sigstore.dev)) even while the
  repo is private. Nothing else leaks, but the repo's existence and
  release tags become public the first time a release is signed.
- **GHCR packages from a private repo start private.** Users can't pull
  them until the packages are made public (owner checklist below).

## Rolling back

Users pin an exact version, so a bad release only reaches hosts whose
owners chose it. There is nothing to re-point for them; the fix is a new
version.

1. **Publish a fixed `X.Y.(Z+1)`** (revert on `main`, bump the pins,
   release as usual). Never re-use or move an `X.Y.Z` tag.
2. **Move `latest` and `X.Y` back** to the previous good release's
   digest, until the fix is out (needs `docker login ghcr.io` with a
   token that has `write:packages`):

   ```sh
   good=$(docker buildx imagetools inspect ghcr.io/pippinmole/upkeep-agent:0.1.0 --format '{{.Manifest.Digest}}')
   docker buildx imagetools create \
     -t ghcr.io/pippinmole/upkeep-agent:latest \
     -t ghcr.io/pippinmole/upkeep-agent:0.1 \
     ghcr.io/pippinmole/upkeep-agent@"$good"
   # or: crane tag ghcr.io/pippinmole/upkeep-agent@"$good" latest
   ```

   Re-tagging keeps the digest, so the old signature and attestations
   still apply.
3. **Delete the bad version** in GHCR: the package's settings, "Manage
   versions", e.g.
   [upkeep-agent versions](https://github.com/users/pippinmole/packages/container/upkeep-agent/versions),
   or `gh api -X DELETE /user/packages/container/upkeep-agent/versions/<id>`
   (`gh api /user/packages/container/upkeep-agent/versions` lists the
   ids). Visibility is per package, not per version, so "make private"
   hides every version of that image; delete the version instead.
4. **Say so** in the GitHub release notes and mark the release as bad.

A signature can't be revoked: a signed digest stays verifiable forever,
and deleting it from GHCR doesn't stop anyone who already pulled it. To
distrust a release, users have to pin a known-good digest (above); tell
them which.

## Owner checklist (account settings, by hand)

These are GitHub settings an agent can't (and shouldn't) change. Do them
before the first release, in this order.

- [ ] **Actions billing / spending limit.** Actions is currently blocked
      on the account, so no workflow (CI or release) runs until it's
      fixed:
      [billing](https://github.com/settings/billing) and
      [spending limits](https://github.com/settings/billing/budgets).
- [ ] **2FA** on the `pippinmole` account (and on any organization that
      later owns the repo or packages), preferably a passkey or security
      key: [account security](https://github.com/settings/security).
- [ ] **Protect `main`** with a branch ruleset
      ([rules](https://github.com/pippinmole/upkeep.sh/settings/rules)):
      target the default branch; require a pull request before merging;
      require status checks to pass (list below); block force pushes;
      restrict deletions. On a private repo, rulesets and branch
      protection need GitHub Pro (or making the repo public).

      Required status checks (from `.github/workflows/ci.yml`; update this
      list when the check names change):
      - `Agent (Go)`
      - `Server (Go)`
      - `Web (Next.js)`
      - `Docker build (agent)`
      - `Docker build (server)`
      - `Docker build (web)`
      - _placeholder: the host-mount check (Stream 3), name TBD_
- [ ] **Protect release tags** with a tag ruleset
      ([rules](https://github.com/pippinmole/upkeep.sh/settings/rules),
      "New tag ruleset"): target `v*`; restrict creations, updates and
      deletions; bypass list: repository admin only. Then only you can
      create a `v*` tag, and nobody can move or delete one.
- [ ] **Actions permissions**
      ([Actions settings](https://github.com/pippinmole/upkeep.sh/settings/actions)):
      "Workflow permissions" = read repository contents and packages
      (read-only default; the release job asks for its own writes); leave
      "Allow GitHub Actions to create and approve pull requests" off.
      Optionally, under "Actions permissions", allow only actions from
      GitHub and verified creators, or require actions pinned to a full
      commit SHA (every workflow here already is).
- [ ] **`release` environment with a required reviewer** (recommended):
      [environments](https://github.com/pippinmole/upkeep.sh/settings/environments).
      The publish job already runs in `environment: release` (GitHub
      creates it, unprotected, on the first release). Add yourself as a
      required reviewer and limit deployment tags to `v*`, so nothing is
      pushed or signed until you approve that run.
- [ ] **After the first release (or rc): make the packages public and
      linked.** GHCR packages pushed from a private repo are private, so
      users can't pull them. For each of
      [upkeep-agent](https://github.com/users/pippinmole/packages/container/upkeep-agent/settings),
      [upkeep-server](https://github.com/users/pippinmole/packages/container/upkeep-server/settings)
      and
      [upkeep-web](https://github.com/users/pippinmole/packages/container/upkeep-web/settings):
      set visibility to **public**; check the package is linked to
      `pippinmole/upkeep.sh` (the `org.opencontainers.image.source` label
      does this on first push); under "Manage Actions access", make sure
      the repo has **write** (only needed if a later push is denied).
- [ ] **Optional: make the repo public.** Turns on GitHub artifact
      attestations and `gh attestation verify`, and branch rulesets on
      the free plan.
