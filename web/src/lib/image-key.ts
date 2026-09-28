// The image detail page's URL and the image key in it
// (docs/tasks/phase-2a-image-vulns.md
// "Dashboard", DOMAIN_MODEL.md §3.8). Client-safe: no database imports.
//
// An image is keyed like container_images: (image_id, os, arch, variant).
// On the containerd image store the id is the image index digest, shared by
// every platform, so the platform is part of the key.
//
// Route: /dashboard/images/-/<image id>?platform=<os>/<arch>[/<variant>]
// (folder `-`, the GitLab-style `/-/` separator). `-` can't clash with the
// `[...repo]` catch-all: Docker repository path components must start with
// a lowercase letter or digit, which is also why the untagged pseudo-repo is
// `_untagged`. (Not `_image`: Next.js treats `_folders` as private, and a
// `%5Fimage` folder only matches the percent-encoded URL.) Tabs are
// `?tab=vulnerabilities` (default: packages); the platform is a search param rather than a path segment because an empty os
// or variant would make an empty segment. Without `platform` the page picks
// the platform the image has on `?host=` (notification links), else the only
// one the user has, else the first and offers the others.

export type ImageKey = { imageId: string; os: string; arch: string; variant: string };

export type ImageTab = "packages" | "vulnerabilities";

export const IMAGE_PAGE_BASE = "/dashboard/images/-";

// sha256:<hex> on Docker; other engines / algorithms keep to the same
// character set. Anything else is rejected before it reaches SQL.
const IMAGE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9:._-]{0,199}$/;

export function isImageId(s: string): boolean {
  return IMAGE_ID_RE.test(s);
}

// The [imageId] route param as the image id. Next.js hands the page the
// segment still percent-encoded ("sha256%3A…") but generateMetadata the
// decoded one, so decode here, once; a malformed escape yields a value
// isImageId rejects.
export function imageIdParam(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

// Platform component: GOOS / GOARCH / variant values, possibly empty.
const PART_RE = /^[A-Za-z0-9._-]{0,40}$/;

// "linux/amd64", "linux/arm64/v8"; an empty os stays as a leading "/".
export function platformParam(k: Pick<ImageKey, "os" | "arch" | "variant">): string {
  return [k.os, k.arch, ...(k.variant ? [k.variant] : [])].join("/");
}

export function parsePlatform(raw: string | null): Omit<ImageKey, "imageId"> | null {
  if (raw === null) return null;
  const parts = raw.split("/");
  if (parts.length < 2 || parts.length > 3 || !parts.every((p) => PART_RE.test(p))) return null;
  return { os: parts[0], arch: parts[1], variant: parts[2] ?? "" };
}

// Human label: "linux/amd64", or "unknown platform" when the engine
// reported none.
export function platformLabel(k: Pick<ImageKey, "os" | "arch" | "variant">): string {
  return [k.os, k.arch, k.variant].filter(Boolean).join("/") || "unknown platform";
}

export function imageHref(
  imageId: string,
  opts: {
    platform?: Pick<ImageKey, "os" | "arch" | "variant"> | null;
    tab?: ImageTab;
    host?: string;
    q?: string;
  } = {},
): string {
  const qs = new URLSearchParams();
  if (opts.platform) qs.set("platform", platformParam(opts.platform));
  if (opts.tab && opts.tab !== "packages") qs.set("tab", opts.tab);
  if (opts.host) qs.set("host", opts.host);
  if (opts.q) qs.set("q", opts.q);
  const s = qs.toString();
  return `${IMAGE_PAGE_BASE}/${encodeURIComponent(imageId)}${s ? `?${s}` : ""}`;
}

// "sha256:0123456789ab…" → "0123456789ab", the length `docker images` shows.
export function shortImageId(id: string): string {
  return id.replace(/^sha256:/, "").slice(0, 12);
}
