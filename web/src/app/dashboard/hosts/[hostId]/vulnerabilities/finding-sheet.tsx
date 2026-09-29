import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { FixCell, KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { AdvisoryList, CveFacts } from "@/components/vuln/cve-facts";
import { AdvisoryLinks, vulnHref } from "@/components/vuln/links";
import { UrlSheet } from "@/components/vuln/url-sheet";
import { ImageFixCell, imageName, imageVulnHref, KindBadge } from "@/components/vuln/where";
import { platformLabel } from "@/lib/image-key";
import type { FindingRow, HostFindingDetail } from "@/lib/queries-vulns";
import { formatDate, formatDateTime } from "@/lib/time";

// The ?v=<vuln_key> sheet on the host Vulnerabilities tab: the CVE, and
// this host's findings for it, host packages first, then the images its
// containers run.
export function FindingSheet({
  hostId,
  vulnKey,
  detail,
  closeHref,
}: {
  hostId: string;
  vulnKey: string;
  detail: HostFindingDetail;
  closeHref: string;
}) {
  return (
    <UrlSheet
      key={vulnKey}
      closeHref={closeHref}
      title={vulnKey}
      description={
        <Link href={vulnHref(vulnKey)} className="underline-offset-4 hover:underline">
          Fleet-wide view of {vulnKey}
        </Link>
      }
    >
      <div className="flex flex-col gap-4">
        <CveFacts cve={detail.cve} />
        <section className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold">On this host</h3>
          <ul className="flex flex-col gap-2">
            {detail.findings.map((f) => (
              <FindingItem
                key={`${f.image?.imageId ?? ""}|${f.image?.os}|${f.image?.arch}|${f.image?.variant}|${f.sourcePackage}`}
                f={f}
                hostId={hostId}
              />
            ))}
          </ul>
        </section>
        <section className="flex flex-col gap-2">
          <h3 className="text-sm font-semibold">Advisories</h3>
          <AdvisoryList advisories={detail.advisories} />
        </section>
      </div>
    </UrlSheet>
  );
}

function FindingItem({ f, hostId }: { f: FindingRow; hostId: string }) {
  return (
    <li className="rounded-lg border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-1.5">
        <SeverityBadge severity={f.severity} />
        {f.isKev && <KevBadge />}
        <KindBadge kind={f.kind} />
        <span className="font-medium">{f.sourcePackage}</span>
        {f.resolvedAt ? <Badge variant="success">Resolved {formatDate(f.resolvedAt)}</Badge> : null}
      </div>
      <dl className="mt-2 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
        {f.image && (
          <>
            <dt className="text-muted-foreground">Image</dt>
            <dd>
              <Link
                href={imageVulnHref(f.image, f.vulnKey, hostId)}
                className="font-medium break-all hover:underline"
              >
                {imageName(f.image)}
              </Link>
              <span className="text-muted-foreground text-xs"> {platformLabel(f.image)}</span>
            </dd>
            <dt className="text-muted-foreground">Containers</dt>
            <dd className="text-xs">{f.image.containers.join(", ") || "—"}</dd>
          </>
        )}
        <dt className="text-muted-foreground">Binaries</dt>
        <dd className="font-mono text-xs">{f.packages.join(", ") || "—"}</dd>
        <dt className="text-muted-foreground">Installed</dt>
        <dd className="font-mono text-xs">{f.installedVersion ?? "—"}</dd>
        <dt className="text-muted-foreground">{f.image ? "Fix" : "Fixed in"}</dt>
        <dd>
          {f.image ? (
            <ImageFixCell fixes={[f]} />
          ) : (
            <FixCell fixedVersion={f.fixedVersion} fixChannel={f.fixChannel} />
          )}
          {f.fixAdvisoryId && <AdvisoryLinks ids={[f.fixAdvisoryId]} className="mt-1" />}
        </dd>
        <dt className="text-muted-foreground">Detected</dt>
        <dd>
          {formatDateTime(f.firstSeenAt)}
          {f.reopenedAt && (
            <span className="text-muted-foreground">
              {" "}
              · reopened {formatDate(f.reopenedAt)}
              {f.reopenCount > 1 && ` (${f.reopenCount}×)`}
            </span>
          )}
        </dd>
        {f.kernelRelease && (
          <>
            <dt className="text-muted-foreground">Kernel</dt>
            <dd className="font-mono text-xs">
              {f.kernelRelease}
              {f.runningKernelUnknown && (
                <span className="text-muted-foreground font-sans"> (running kernel unknown)</span>
              )}
            </dd>
          </>
        )}
      </dl>
    </li>
  );
}
