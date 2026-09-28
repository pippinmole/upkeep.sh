import { UNTAGGED_REPO } from "@/lib/queries-docker-fleet";

// /dashboard/images/<repo path>: repository names contain slashes
// ("ghcr.io/me/api"), so each path component is its own segment of the
// [...repo] catch-all. '' (untagged images) maps to UNTAGGED_REPO.
export function repoHref(
  repo: string,
  filter?: { tag?: string; digest?: string; image?: string },
): string {
  const path = (repo || UNTAGGED_REPO).split("/").map(encodeURIComponent).join("/");
  const qs = new URLSearchParams();
  if (filter?.tag) qs.set("tag", filter.tag);
  if (filter?.digest) qs.set("digest", filter.digest);
  if (filter?.image) qs.set("image", filter.image);
  const s = qs.toString();
  return `/dashboard/images/${path}${s ? `?${s}` : ""}`;
}
