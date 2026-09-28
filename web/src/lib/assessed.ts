// Which packages the matcher compares against advisories at all.
//
// MIRROR of server/internal/matcher/ecosystems.go (`ecosystems` and
// `Assessed`): the one Go list of assessed ecosystems, keyed by
// software_versions.ecosystem (the purl type), with the distros whose
// advisories are imported for it. Keep this table in step with the Go map.
// If an ecosystem is added there (npm, PyPI, Go…) and not here, the
// dashboard keeps labelling its packages "not assessed", which is the safe
// side; the reverse would show unmatched packages as clean, so never add
// one here first. Image scores' not_assessed_count comes from the Go side.
//
// Everything else is inventoried but "not assessed", never "no
// vulnerabilities". Whether a release is still supported (advisories
// imported) is data: join distro_releases (supported) on
// (distro, codename = release), as the Go comment says.
export const ASSESSED_ECOSYSTEMS: Readonly<Record<string, readonly string[]>> = {
  deb: ["debian", "ubuntu"],
  apk: ["alpine"],
};

// matcher.Assessed: the ecosystem has a comparator and the distro's
// advisories are imported for it, and a distro-scoped package has a
// release (one interned with an empty release can't be joined to
// per-release advisories).
export function isAssessed(ecosystem: string, distro: string, release: string): boolean {
  const distros = ASSESSED_ECOSYSTEMS[ecosystem];
  if (!distros || !distros.includes(distro)) return false;
  return distro === "" || release !== "";
}

// Distros some assessed ecosystem covers ("is this distro assessed at all").
export function isAssessedDistro(distro: string): boolean {
  return Object.values(ASSESSED_ECOSYSTEMS).some((ds) => ds.includes(distro));
}

const lit = (s: string) => `'${s.replaceAll("'", "''")}'`;

// isAssessed as a SQL boolean over three text columns, generated from the
// same table (constants only; no user input reaches it).
export function assessedSql(ecosystem: string, distro: string, release: string): string {
  const arms = Object.entries(ASSESSED_ECOSYSTEMS).map(
    ([eco, distros]) =>
      `(${ecosystem} = ${lit(eco)} AND ${distro} IN (${distros.map(lit).join(", ")}))`,
  );
  return `((${arms.join(" OR ")}) AND (${distro} = '' OR ${release} <> ''))`;
}
