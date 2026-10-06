// Where an image package comes from, for the image tools
// (docs/MCP.md#tools). upkeep.sh doesn't record which layer installed a
// package, so this is the ecosystem's answer, not the layer's: a distro
// package (deb, apk, rpm) belongs to the image's OS, nearly always from
// the base image, and is fixed by moving FROM to a newer base tag (or an
// upgrade step in the build); a language package (npm, PyPI, Go, …) at
// its paths is usually the application's own dependency, fixed by bumping
// it and rebuilding.

export const ORIGINS = ["os", "application"] as const;
export type Origin = (typeof ORIGINS)[number];

const OS_ECOSYSTEMS = new Set(["deb", "apk", "rpm"]);

export function originOf(ecosystem: string): Origin {
  return OS_ECOSYSTEMS.has(ecosystem) ? "os" : "application";
}

export const ORIGIN_HELP =
  "os: a distro package of the image's OS (deb, apk, rpm), nearly always from the base image: " +
  "fixed by a newer base image tag in FROM, or an upgrade step in the build; application: a " +
  "language package (npm, PyPI, Go, …) at the listed paths, usually the application's own " +
  "dependency: fixed by bumping it. Told by ecosystem, not by layer";
