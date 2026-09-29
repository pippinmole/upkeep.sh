import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { ReleaseNotAssessedBadge } from "@/components/image/release-badge";
import { KevBadge, SeverityBadge } from "@/components/vuln/badges";
import { imageScoreState, type ImageScore } from "@/lib/image-score";
import { SEVERITIES, SEVERITY_LABEL } from "@/lib/severity";
import { cn } from "@/lib/utils";

// Compact image score for table cells (fleet Images, host Images and
// Containers): worst severity bucket with its count, KEV, total and max
// CVSS; or why there is no score. Links to the image detail page. No hooks,
// so it renders in server and client tables alike.

// Prefer <Badge variant="success">; kept for callers that add it to an
// outline Badge's className.
export const CLEAN_BADGE = "border-success/40 bg-success/10 font-normal text-success-fg";

export function scoreTitle(s: ImageScore): string {
  const parts = SEVERITIES.filter((sev) => s.counts[sev] > 0).map(
    (sev) => `${s.counts[sev]} ${SEVERITY_LABEL[sev].toLowerCase()}`,
  );
  return [
    parts.join(", "),
    s.kev > 0 && `${s.kev} known exploited (KEV)`,
    s.fixable > 0 && `${s.fixable} with a fix`,
    s.maxCvss !== null && `max CVSS ${s.maxCvss.toFixed(1)}`,
    (s.notAssessed ?? 0) > 0 && `${s.notAssessed} packages not assessed`,
  ]
    .filter(Boolean)
    .join(" · ");
}

function Muted({ children, title }: { children: React.ReactNode; title?: string }) {
  return (
    <span className={cn("text-muted-foreground text-xs", title && "cursor-help")} title={title}>
      {children}
    </span>
  );
}

export function ImageScoreCell({
  score,
  inspected,
  hasRepoDigest,
  href,
}: {
  score: ImageScore | null;
  inspected: boolean;
  hasRepoDigest: boolean;
  href: string | null;
}) {
  const st = imageScoreState(score, { inspected, hasRepoDigest });
  let body: React.ReactNode;
  switch (st.kind) {
    case "not_inspected":
      body = (
        <Muted title="The platform isn't known until the agent inspects the image">
          Not inspected
        </Muted>
      );
      break;
    case "none":
      body = st.local ? (
        <Muted title="Built locally or loaded (no repo digest): the server can't fetch its package list; the agent will send it">
          Local image, needs the agent
        </Muted>
      ) : (
        <Muted title="The server hasn't fetched this image's package list yet">
          No package list yet
        </Muted>
      );
      break;
    case "unavailable":
      body = <Muted title={st.reason}>{st.needsAgent ? "Needs the agent" : st.reason}</Muted>;
      break;
    case "error":
      body = <Muted title={st.reason}>Fetch failed, retrying</Muted>;
      break;
    case "scoring":
      body = <Muted title="The package list is being matched against advisories">Scoring…</Muted>;
      break;
    case "release_not_assessed":
      body = <ReleaseNotAssessedBadge st={st} />;
      break;
    case "no_known":
      body = (
        <div className="flex flex-col items-start gap-0.5">
          <Badge variant="success" className="font-normal whitespace-nowrap">
            No known vulnerabilities
          </Badge>
          {st.partial && score && (
            <Muted title="Packages in ecosystems the matcher doesn't cover yet">
              {score.notAssessed} of {score.packages} not assessed
            </Muted>
          )}
        </div>
      );
      break;
    case "vulnerable": {
      const s = score!;
      const worst = s.worst ?? "unknown";
      body = (
        <div className="flex flex-col items-start gap-0.5" title={scoreTitle(s)}>
          <div className="flex flex-wrap items-center gap-1">
            <SeverityBadge severity={worst} count={s.counts[worst]} />
            {s.kev > 0 && <KevBadge count={s.kev > 1 ? s.kev : undefined} />}
          </div>
          <span className="text-muted-foreground text-xs whitespace-nowrap">
            {s.vulns} {s.vulns === 1 ? "vulnerability" : "vulnerabilities"}
            {s.maxCvss !== null && ` · CVSS ${s.maxCvss.toFixed(1)}`}
          </span>
        </div>
      );
      break;
    }
  }
  if (!href) return body;
  return (
    <Link
      href={href}
      className="block w-fit rounded-sm hover:opacity-80"
      title="Packages and vulnerabilities"
    >
      {body}
    </Link>
  );
}
