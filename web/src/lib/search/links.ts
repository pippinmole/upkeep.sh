// Destinations for search results. Plain functions with no imports, so the
// result mapping stays testable and client-safe. They mirror
// components/vuln/links.tsx (vulnHref) and components/docker-fleet/links.ts
// (repoHref), which pull in React and the database pool respectively.

export function vulnDetailHref(vulnKey: string): string {
  return `/dashboard/vulnerabilities/${encodeURIComponent(vulnKey)}`;
}

export function packageHref(name: string): string {
  return `/dashboard/packages/${encodeURIComponent(name)}`;
}

// Repository names contain slashes, one [...repo] segment each.
export function imageRepoHref(repo: string): string {
  return `/dashboard/images/${repo.split("/").map(encodeURIComponent).join("/")}`;
}

// The filtered fleet lists, for "show everything matching".
export function listHref(list: "vulnerabilities" | "packages" | "images", q: string): string {
  return `/dashboard/${list}?q=${encodeURIComponent(q)}`;
}
