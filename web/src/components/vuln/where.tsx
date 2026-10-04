import { Container, Package } from "lucide-react";
import Link from "next/link";

import { EcosystemIcon } from "@/components/brand";
import { Badge } from "@/components/ui/badge";
import { imageHref, platformLabel, shortImageId } from "@/lib/image-key";
import type { ImageOrigin, ImageWhere, VulnKind } from "@/lib/vuln-tables";

import { NoFixBadge } from "./badges";

// Where a finding is, for the Vulnerabilities lists and the CVE page
// (DOMAIN_MODEL.md §3.5, §3.6): in a host package (fixed by upgrading the
// host) or in a container image (fixed by rebuilding or re-pulling the
// image). Server-safe: used from Server and Client Components.

export function KindBadge({ kind }: { kind: VulnKind }) {
  const Icon = kind === "image" ? Container : Package;
  return (
    <Badge variant="outline" className="text-muted-foreground gap-1 font-normal whitespace-nowrap">
      <Icon aria-hidden />
      {kind === "image" ? "Image" : "Host package"}
    </Badge>
  );
}

// The image detail page's Vulnerabilities tab filtered to the CVE (the
// shape store.ImageFindingURL links notifications to, plus the platform).
export function imageVulnHref(image: ImageWhere, vulnKey: string, hostId?: string): string {
  return imageHref(image.imageId, {
    platform: image,
    tab: "vulnerabilities",
    q: vulnKey,
    host: hostId,
  });
}

export function imageName(image: Pick<ImageWhere, "imageId" | "refs">): string {
  return image.refs[0] ?? shortImageId(image.imageId);
}

// Image ref (linked), other refs, platform and the containers using it.
export function ImageWhereCell({
  image,
  vulnKey,
  hostId,
}: {
  image: ImageWhere;
  vulnKey: string;
  hostId?: string;
}) {
  const more = image.refs.length - 1;
  return (
    <div className="flex max-w-64 flex-col items-start gap-0.5">
      <KindBadge kind="image" />
      <Link
        href={imageVulnHref(image, vulnKey, hostId)}
        className="font-medium break-all hover:underline"
        title={image.refs.join(", ") || image.imageId}
      >
        {imageName(image)}
      </Link>
      <span className="text-muted-foreground text-xs">
        {platformLabel(image)}
        {more > 0 && ` · +${more} more ${more === 1 ? "tag" : "tags"}`}
      </span>
      {image.containers.length > 0 && (
        <span
          className="text-muted-foreground line-clamp-2 text-xs whitespace-normal"
          title={image.containers.join(", ")}
        >
          {image.containers.length === 1 ? "container" : "containers"} {image.containers.join(", ")}
        </span>
      )}
    </div>
  );
}

// Distro package types: their SBOM paths are only the package database,
// so the origin names the package manager instead of a path.
const DISTRO_ECOSYSTEMS: Record<string, string> = {
  deb: "Debian package",
  apk: "Alpine package",
  rpm: "RPM package",
};

const LANGUAGE_NAMES: Record<string, string> = {
  golang: "Go",
  npm: "npm",
  pypi: "Python",
  maven: "Java",
  cargo: "Rust",
  gem: "Ruby",
  nuget: ".NET",
  composer: "PHP",
};

const MAX_ORIGIN_PATHS = 2;

// Where the vulnerable package sits inside the image: a distro package, or
// a language package and the binary / manifest it was found in (e.g. Go's
// stdlib in /usr/local/bin/gosu). Says whose release carries the fix.
export function ImageOriginLine({ origin }: { origin: ImageOrigin }) {
  const distro = DISTRO_ECOSYSTEMS[origin.ecosystem];
  const lang = LANGUAGE_NAMES[origin.ecosystem] ?? origin.ecosystem;
  const paths = distro ? [] : origin.paths;
  return (
    <span className="text-muted-foreground flex max-w-64 items-start gap-1 text-xs">
      <EcosystemIcon ecosystem={origin.ecosystem} size={12} className="mt-0.5 shrink-0" />
      {distro ?? (
        <span className="flex min-w-0 flex-col" title={paths.join("\n") || undefined}>
          <span>
            {lang}
            {paths.length > 0 && " in"}
          </span>
          {paths.slice(0, MAX_ORIGIN_PATHS).map((p) => (
            <span key={p} className="truncate font-mono">
              {p}
            </span>
          ))}
          {paths.length > MAX_ORIGIN_PATHS && <span>+{paths.length - MAX_ORIGIN_PATHS} more</span>}
        </span>
      )}
    </span>
  );
}

// "Rebuild or re-pull the image; <package> fixed in <version>", and where
// each package sits in the image. An image finding is fixed by a new
// image, not by upgrading the host.
export function ImageFixCell({
  fixes,
}: {
  fixes: {
    sourcePackage: string | null;
    fixedVersion: string | null;
    origin?: ImageOrigin | null;
  }[];
}) {
  const fixed = fixes.filter((f) => f.fixedVersion);
  const unfixed = fixes.filter((f) => !f.fixedVersion);
  return (
    <div className="flex flex-col items-start gap-1">
      {fixed.length > 0 && (
        <span className="text-sm whitespace-nowrap">Rebuild or re-pull image</span>
      )}
      {fixed.map((f) => (
        <div key={f.sourcePackage} className="flex flex-col items-start gap-0.5">
          <span className="text-muted-foreground text-xs">
            {f.sourcePackage} fixed in <span className="font-mono">{f.fixedVersion}</span>
          </span>
          {f.origin && <ImageOriginLine origin={f.origin} />}
        </div>
      ))}
      {unfixed.length > 0 && <NoFixBadge />}
      {unfixed.map(
        (f) =>
          f.origin && (
            <div key={f.sourcePackage} className="flex flex-col items-start gap-0.5">
              {fixes.length > 1 && (
                <span className="text-muted-foreground text-xs">{f.sourcePackage}</span>
              )}
              <ImageOriginLine origin={f.origin} />
            </div>
          ),
      )}
    </div>
  );
}
