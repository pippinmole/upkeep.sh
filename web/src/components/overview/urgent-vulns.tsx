import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { vulnHref } from "@/components/vuln/links";
import { imageHref, shortImageId } from "@/lib/image-key";
import type { UrgentVulnRow } from "@/lib/queries-overview-images";

import { plural } from "./cards";

// "Most urgent vulnerabilities" over both finding kinds, each row saying
// where the CVE is: in host packages (upgrade the host) and/or in images
// (rebuild or re-pull). The CVE page lists host findings only
// (docs/tasks/phase-2a-image-vulns.md), so an image-only CVE in one image
// links to that image's
// Vulnerabilities tab filtered to it.

function imageLink(r: UrgentVulnRow): string {
  if (r.images === 1 && r.topImage) {
    return imageHref(r.topImage.imageId, {
      platform: r.topImage,
      tab: "vulnerabilities",
      q: r.vulnKey,
    });
  }
  return "/dashboard/images";
}

function Where({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <span className="text-muted-foreground inline-flex items-center gap-1.5 text-sm">
      <Badge variant="outline" className="font-normal whitespace-nowrap">
        {label}
      </Badge>
      {children}
    </span>
  );
}

export function UrgentVulns({ rows }: { rows: UrgentVulnRow[] }) {
  return (
    <section className="flex flex-col gap-2">
      <div className="flex items-baseline justify-between gap-2">
        <h2 className="font-semibold">Most urgent vulnerabilities</h2>
        <Link
          href="/dashboard/vulnerabilities"
          className="text-muted-foreground hover:text-foreground text-sm hover:underline"
        >
          View all
        </Link>
      </div>
      {rows.length === 0 ? (
        <p className="text-muted-foreground text-sm">Nothing open.</p>
      ) : (
        <ul className="bg-card divide-y rounded-lg border">
          {rows.map((r) => {
            const inHost = r.hostPackageHosts > 0;
            const imgName = r.topImage
              ? (r.topImage.refs[0] ?? shortImageId(r.topImage.imageId))
              : null;
            return (
              <li
                key={r.vulnKey}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5"
              >
                <Link
                  href={inHost ? vulnHref(r.vulnKey) : imageLink(r)}
                  className="font-medium hover:underline"
                >
                  {r.vulnKey}
                </Link>
                <SeverityBadge severity={r.severity} />
                {r.isKev && <KevBadge />}
                {inHost && (
                  <Where label="Host package">
                    {r.hostPackages.join(", ")} · {plural(r.hostPackageHosts, "host", "hosts")}
                  </Where>
                )}
                {r.images > 0 && (
                  <Where label="Image">
                    <Link href={imageLink(r)} className="hover:text-foreground hover:underline">
                      {r.images === 1 && imgName ? imgName : plural(r.images, "image", "images")}
                    </Link>
                    {r.imagePackages.length > 0 && ` · ${r.imagePackages.join(", ")}`}
                    {" · "}
                    {plural(r.imageHosts, "host", "hosts")}
                  </Where>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
