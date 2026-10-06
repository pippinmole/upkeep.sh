import * as z from "zod";

import { pool } from "@/lib/db";
import {
  imageHref,
  type ImageKey,
  parsePlatform,
  platformLabel,
  platformParam,
  shortImageId,
} from "@/lib/image-key";
import { isUuid } from "@/lib/queries-inventory";

import { ToolError, type ToolContext } from "./tool";

// Hosts are addressed by id or hostname (docs/MCP.md#tools). A hostname
// several hosts share is an error listing the candidates, never a guess.
// Archived hosts aren't addressable, as on the dashboard's lists.

export type ResolvedHost = { id: string; hostname: string; label: string | null };

export type HostLookup = (workspaceId: string, ref: string) => Promise<ResolvedHost[]>;

const CANDIDATES_LISTED = 10;

const lookupHosts: HostLookup = async (workspaceId, ref) => {
  const { rows } = await pool.query<ResolvedHost>(
    isUuid(ref)
      ? `SELECT id, hostname, label FROM hosts
         WHERE workspace_id = $1 AND archived_at IS NULL AND id = $2::uuid`
      : `SELECT id, hostname, label FROM hosts
         WHERE workspace_id = $1 AND archived_at IS NULL AND lower(hostname) = lower($2)
         ORDER BY hostname, id
         LIMIT ${CANDIDATES_LISTED + 1}`,
    [workspaceId, ref],
  );
  return rows;
};

export async function resolveHost(
  workspaceId: string,
  ref: string,
  lookup: HostLookup = lookupHosts,
): Promise<ResolvedHost> {
  const hosts = await lookup(workspaceId, ref);
  if (hosts.length === 1) return hosts[0];
  if (hosts.length === 0) {
    throw new ToolError(
      `No host with the id or hostname ${JSON.stringify(ref)} in this workspace. Check the ` +
        "hostname, or pass the host's id.",
    );
  }
  const shown = hosts
    .slice(0, CANDIDATES_LISTED)
    .map((h) => `${h.hostname}${h.label ? ` (${h.label})` : ""}: ${h.id}`);
  const more = hosts.length > CANDIDATES_LISTED ? "; and more" : "";
  throw new ToolError(
    `Several hosts are named ${JSON.stringify(ref)}; pass one of their ids instead: ` +
      `${shown.join("; ")}${more}.`,
  );
}

// The host a host tool answered for, as every host tool returns it.
export const hostRef = z.object({
  id: z.string(),
  hostname: z.string(),
  label: z.string().nullable(),
  dashboard_url: z.string(),
});

export function hostRefOf(
  host: { id: string; hostname: string; label: string | null },
  ctx: ToolContext,
): z.input<typeof hostRef> {
  return {
    id: host.id,
    hostname: host.hostname,
    label: host.label,
    dashboard_url: ctx.dashboardUrl(`/dashboard/hosts/${host.id}`),
  };
}

// "web-01 (eu)" for the text renderings.
export function hostName(host: { hostname: string; label: string | null }): string {
  return host.label ? `${host.hostname} (${host.label})` : host.hostname;
}

// Images are addressed by id ("sha256:…", or the 12+ character short id
// `docker images` shows), by digest ("sha256:…" of a repo digest), or by
// reference: "repo:tag", "repo@sha256:…", or a bare "repo" for any of its
// tags. Docker Hub names match with or without "docker.io/" and
// "library/". Only inspected images (platform known) on the workspace's
// non-archived hosts are addressable, as on the image pages; one id can
// have several platforms, which `platform` ("linux/arm64") picks between.

export type ResolvedImage = {
  key: ImageKey;
  // Tags and repo digests across the workspace's hosts, sorted.
  refs: string[];
};

export type ImageLookup = (
  workspaceId: string,
  ref: string,
  platform: Omit<ImageKey, "imageId"> | null,
) => Promise<ResolvedImage[]>;

const SHORT_ID_RE = /^(sha256:)?[0-9a-f]{12,64}$/;

// The forms a repository name is stored under: Docker keeps Hub images as
// "nginx" or "org/app", other registries with their host.
export function repoForms(repo: string): string[] {
  const short = repo.replace(/^(docker\.io|index\.docker\.io|registry-1\.docker\.io)\//, "");
  const bare = short.replace(/^library\/(?=[^/]+$)/, "");
  const forms = new Set([repo, short, bare]);
  if (!bare.includes("/")) forms.add(`library/${bare}`);
  if (!/^[^/]+[.:][^/]*\//.test(bare) && !bare.startsWith("localhost/")) {
    forms.add(`docker.io/${bare}`);
    if (!bare.includes("/")) forms.add(`docker.io/library/${bare}`);
  }
  return [...forms];
}

// A reference split into what the lookup matches: full tags
// ("repo:tag"), repo digests ("repo@sha256:…"), or a bare repository.
export function parseImageRef(ref: string): { tags: string[]; digests: string[]; repos: string[] } {
  const at = ref.indexOf("@");
  if (at > 0) {
    const digest = ref.slice(at + 1);
    return {
      tags: [],
      digests: repoForms(ref.slice(0, at)).map((r) => `${r}@${digest}`),
      repos: [],
    };
  }
  const tag = /:([^:/]+)$/.exec(ref);
  if (tag) {
    const repo = ref.slice(0, tag.index);
    return { tags: repoForms(repo).map((r) => `${r}:${tag[1]}`), digests: [], repos: [] };
  }
  return { tags: [], digests: [], repos: repoForms(ref) };
}

const lookupImages: ImageLookup = async (workspaceId, ref, platform) => {
  const { tags, digests, repos } = parseImageRef(ref);
  const shortId = SHORT_ID_RE.test(ref) ? ref.replace(/^sha256:/, "") : null;
  const { rows } = await pool.query<{
    image_id: string;
    os: string;
    arch: string;
    variant: string;
    refs: string[] | null;
  }>(
    `WITH hk AS (
       SELECT hi.image_id, hi.os, hi.arch, hi.variant, hi.repo_tags, hi.repo_digests
       FROM hosts h
       JOIN host_images hi ON hi.host_id = h.id AND hi.removed_at IS NULL
       WHERE h.workspace_id = $1 AND h.archived_at IS NULL AND hi.os IS NOT NULL
     ),
     m AS (
       SELECT DISTINCT image_id, os, arch, variant FROM hk
       WHERE (image_id = $2
              OR ($3::text IS NOT NULL AND starts_with(image_id, 'sha256:' || $3))
              OR EXISTS (SELECT 1 FROM unnest(repo_digests) d
                         WHERE d = ANY($5) OR split_part(d, '@', 2) = $2)
              OR EXISTS (SELECT 1 FROM unnest(repo_tags) t
                         WHERE t = ANY($4) OR regexp_replace(t, ':[^:/]+$', '') = ANY($6)))
         AND ($7::text IS NULL OR (os = $7 AND arch = $8 AND variant = $9))
     )
     SELECT m.image_id, m.os, m.arch, m.variant,
            (SELECT array_agg(DISTINCT r ORDER BY r)
             FROM hk, unnest(hk.repo_tags || hk.repo_digests) r
             WHERE hk.image_id = m.image_id AND hk.os = m.os AND hk.arch = m.arch
               AND hk.variant = m.variant AND r NOT IN ('<none>:<none>', '<none>@<none>')) AS refs
     FROM m
     ORDER BY m.image_id, m.os, m.arch, m.variant
     LIMIT ${CANDIDATES_LISTED + 1}`,
    [
      workspaceId,
      ref,
      shortId,
      tags,
      digests,
      repos,
      platform?.os ?? null,
      platform?.arch ?? null,
      platform?.variant ?? null,
    ],
  );
  return rows.map((r) => ({
    key: { imageId: r.image_id, os: r.os, arch: r.arch, variant: r.variant },
    refs: r.refs ?? [],
  }));
};

export async function resolveImage(
  workspaceId: string,
  ref: string,
  platform: string | null = null,
  lookup: ImageLookup = lookupImages,
): Promise<ResolvedImage> {
  const p = platform === null ? null : parsePlatform(platform);
  if (platform !== null && !p) {
    throw new ToolError(
      `${JSON.stringify(platform)} isn't a platform; pass it as os/arch[/variant], e.g. "linux/arm64".`,
    );
  }
  const images = await lookup(workspaceId, ref, p);
  if (images.length === 1) return images[0];
  const on = platform === null ? "" : ` for ${platform}`;
  if (images.length === 0) {
    throw new ToolError(
      `No image with the id, digest or reference ${JSON.stringify(ref)}${on} on this ` +
        "workspace's hosts. list_images shows the images and their ids.",
    );
  }
  const shown = images
    .slice(0, CANDIDATES_LISTED)
    .map((im) => `${imageName(im)}: ${im.key.imageId} platform ${platformParam(im.key)}`);
  const more = images.length > CANDIDATES_LISTED ? "; and more" : "";
  throw new ToolError(
    `Several images match ${JSON.stringify(ref)}${on}; pass one of their ids, with platform when ` +
      `an id has several: ${shown.join("; ")}${more}.`,
  );
}

const REFS_LISTED = 5;

// The image an image tool answered for, as every image tool returns it.
export const imageRef = z.object({
  id: z.string().describe("Pass it (with platform) to the image tools"),
  platform: z.string().describe('os/arch[/variant], e.g. "linux/amd64"'),
  refs: z.array(z.string()).describe("Tags and repo digests on the workspace's hosts"),
  more_refs: z.number(),
  dashboard_url: z.string(),
});

export function imageRefOf(
  im: ResolvedImage,
  ctx: ToolContext,
  tab: "packages" | "vulnerabilities" = "packages",
): z.input<typeof imageRef> {
  return {
    id: im.key.imageId,
    platform: platformLabel(im.key),
    refs: im.refs.slice(0, REFS_LISTED),
    more_refs: Math.max(0, im.refs.length - REFS_LISTED),
    dashboard_url: ctx.dashboardUrl(imageHref(im.key.imageId, { platform: im.key, tab })),
  };
}

// "nginx:1.27 (linux/amd64)", or the short id for an untagged image, for
// the text renderings.
export function imageName(im: { key: ImageKey; refs: string[] }): string {
  return `${refLabel(im.refs, im.key.imageId)} (${platformLabel(im.key)})`;
}

// An image's first tag, else its first digest, else its short id.
export function refLabel(refs: string[], imageId: string): string {
  return refs.find((r) => !r.includes("@")) ?? refs[0] ?? shortImageId(imageId);
}
