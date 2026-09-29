import { Container, Package } from "lucide-react";
import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { imageHref, platformLabel, shortImageId } from "@/lib/image-key";
import type { ImageWhere, VulnKind } from "@/lib/vuln-tables";

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

// "Rebuild or re-pull the image; fixed in <package> <version>". An image
// finding is fixed by a new image, not by upgrading the host.
export function ImageFixCell({
  fixes,
}: {
  fixes: { sourcePackage: string | null; fixedVersion: string | null }[];
}) {
  const fixed = fixes.filter((f) => f.fixedVersion);
  if (fixed.length === 0) return <NoFixBadge />;
  const unfixed = fixes.length - fixed.length;
  return (
    <div className="flex flex-col items-start gap-0.5">
      <span className="text-sm whitespace-nowrap">Rebuild or re-pull image</span>
      {fixed.map((f) => (
        <span key={f.sourcePackage} className="text-muted-foreground text-xs">
          fixed in {fixed.length > 1 || unfixed > 0 ? `${f.sourcePackage} ` : ""}
          <span className="font-mono">{f.fixedVersion}</span>
        </span>
      ))}
      {unfixed > 0 && <NoFixBadge />}
    </div>
  );
}
