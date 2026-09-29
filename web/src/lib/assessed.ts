// Which packages the matcher compares against advisories at all.
//
// MIRROR of server/internal/matcher/ecosystems.go (`ecosystems`,
// `Assessed` and `ReleaseStatusOf`): the one Go list of assessed
// ecosystems, keyed by software_versions.ecosystem (the purl type), with
// the distros whose advisories are imported for it. Keep this table in
// step with the Go map. If an ecosystem is added there (npm, PyPI, Go…)
// and not here, the dashboard keeps labelling its packages "not assessed",
// which is the safe side; the reverse would show unmatched packages as
// clean, so never add one here first. Image scores' not_assessed_count
// comes from the Go side.
//
// Everything else is inventoried but "not assessed", never "no
// vulnerabilities". Advisories are imported only for supported releases,
// so a distro package is assessed only when distro_releases has its
// release with supported = true: join distro_releases on
// (distro, codename = release) and pass `supported` (null = no row).
export const ASSESSED_ECOSYSTEMS: Readonly<Record<string, readonly string[]>> = {
  deb: ["debian", "ubuntu"],
  apk: ["alpine"],
  npm: [""], // language ecosystems: no distro
};

// matcher.Assessed: the ecosystem has a comparator, the distro's
// advisories are imported for it, and a distro-scoped package has a
// release that is still supported (supported is ignored for packages
// without a distro). A package interned with an empty release can't be
// joined to per-release advisories either.
export function isAssessed(
  ecosystem: string,
  distro: string,
  release: string,
  supported: boolean | null,
): boolean {
  const distros = ASSESSED_ECOSYSTEMS[ecosystem];
  if (!distros || !distros.includes(distro)) return false;
  return distro === "" || (release !== "" && supported === true);
}

// Distros some assessed ecosystem covers ("is this distro assessed at all").
export function isAssessedDistro(distro: string): boolean {
  return Object.values(ASSESSED_ECOSYSTEMS).some((ds) => ds.includes(distro));
}

// matcher.ReleaseStatus: how a distro release stands, from its
// distro_releases row (supported; null = not in the table).
export type ReleaseStatus = "supported" | "out_of_support" | "unknown";

export function releaseStatusOf(supported: boolean | null): ReleaseStatus {
  if (supported === null) return "unknown";
  return supported ? "supported" : "out_of_support";
}

const lit = (s: string) => `'${s.replaceAll("'", "''")}'`;

// isAssessed as a SQL boolean over three text columns and the release's
// distro_releases.supported (NULL = no row), generated from the same table
// (constants only; no user input reaches it).
export function assessedSql(
  ecosystem: string,
  distro: string,
  release: string,
  supported: string,
): string {
  const arms = Object.entries(ASSESSED_ECOSYSTEMS).map(
    ([eco, distros]) =>
      `(${ecosystem} = ${lit(eco)} AND ${distro} IN (${distros.map(lit).join(", ")}))`,
  );
  return `((${arms.join(" OR ")}) AND (${distro} = '' OR (${release} <> '' AND coalesce(${supported}, false))))`;
}
