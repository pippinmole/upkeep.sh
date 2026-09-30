// The agent image the dashboard's install command runs. The one place
// the web app pins it: bump it (and agent/docker-compose.example.yml's
// `image:` line) with `scripts/check-version-pins.sh --set X.Y.Z`, and
// release.yml refuses a `vX.Y.Z` tag that doesn't match both
// (docs/RELEASING.md). Always an exact version, never `:latest`, so a bad
// release doesn't reach hosts that didn't choose it.
export const DEFAULT_AGENT_IMAGE = "ghcr.io/pippinmole/upkeep-agent:0.1.1";

// SW_AGENT_IMAGE overrides it for self-hosters who mirror images into
// their own registry. Read on the server at request time (the install
// command comes from the issueEnrollmentToken server action), so it's a
// runtime setting of the web container, not baked into the bundle.
export function resolveAgentImage(env: Record<string, string | undefined> = process.env): string {
  return env.SW_AGENT_IMAGE?.trim() || DEFAULT_AGENT_IMAGE;
}
