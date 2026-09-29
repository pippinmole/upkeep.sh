import { Container, Package } from "lucide-react";
import Link from "next/link";

import { plural } from "@/components/overview/cards";
import { KevBadge } from "@/components/vuln/badges";
import type { FleetVulnCounts } from "@/lib/queries-vuln-list";
import type { VulnKind } from "@/lib/vuln-tables";

// Open vulnerabilities per kind above the fleet list, side by side and
// never summed (DOMAIN_MODEL.md §3.6): a host package is fixed by
// upgrading the host, an image by rebuilding or re-pulling it. Each links
// to the list narrowed to that kind.
export function KindSummary({ counts, basePath }: { counts: FleetVulnCounts; basePath: string }) {
  const items: { kind: VulnKind; title: string; fix: string; where: string }[] = [
    {
      kind: "package",
      title: "Host packages",
      fix: "fixed by upgrading the host",
      where: `on ${plural(counts.package.hosts, "host", "hosts")}`,
    },
    {
      kind: "image",
      title: "Container images",
      fix: "fixed by rebuilding or re-pulling the image",
      where: `in ${plural(counts.image.images, "image", "images")} on ${plural(counts.image.hosts, "host", "hosts")}`,
    },
  ];
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {items.map((it) => {
        const c = counts[it.kind];
        const Icon = it.kind === "image" ? Container : Package;
        return (
          <div key={it.kind} className="bg-card flex flex-col gap-1 rounded-lg border px-4 py-3">
            <div className="flex flex-wrap items-center gap-2 text-sm">
              <Icon className="text-muted-foreground size-4" aria-hidden />
              <Link href={`${basePath}?kind=${it.kind}`} className="font-medium hover:underline">
                {it.title}
              </Link>
              {c.kev > 0 && (
                <Link
                  href={`${basePath}?kind=${it.kind}&kev=1`}
                  title={`Known-exploited findings on ${plural(c.kevHosts, "host", "hosts")}`}
                >
                  <KevBadge count={c.kev} />
                </Link>
              )}
            </div>
            <p className="text-sm">
              {c.vulns === 0 ? (
                <span className="text-muted-foreground">No open vulnerabilities</span>
              ) : (
                <>
                  <span className="font-semibold tabular-nums">
                    {c.vulns.toLocaleString("en-US")}
                  </span>{" "}
                  {c.vulns === 1 ? "vulnerability" : "vulnerabilities"}{" "}
                  <span className="text-muted-foreground">{it.where}</span>
                </>
              )}
            </p>
            <p className="text-muted-foreground text-xs">{it.fix}</p>
          </div>
        );
      })}
    </div>
  );
}
