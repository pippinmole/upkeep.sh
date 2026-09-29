import { AlertTriangle, Clock, Info, PackageX } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  RELEASE_NOT_ASSESSED_LABEL,
  releaseName,
  releaseNotAssessed,
  releaseNotAssessedText,
  SBOM_REASON_PRIVATE,
} from "@/lib/image-score";
import type { ImageOverview } from "@/lib/queries-image";
import { formatDate, formatDateTime } from "@/lib/time";

// Why the image has no package list, or why its list says less than it
// seems: explicit states instead of empty tables
// (docs/tasks/phase-2a-image-vulns.md
// "Dashboard"). Returns null when the list is ok, scored and assessed.

export type ListView =
  // Show the Packages / Vulnerabilities tabs (an ok list).
  | "tables"
  // No list: show only the state.
  | "state";

export function listView(o: ImageOverview): ListView {
  return o.list?.status === "ok" ? "tables" : "state";
}

export function ImageListStateNote({ overview }: { overview: ImageOverview }) {
  const { list, score, digests } = overview;
  if (!list) {
    return digests.length === 0 ? (
      <Alert>
        <PackageX className="size-4" />
        <AlertTitle>Private or local image, needs the agent</AlertTitle>
        <AlertDescription>
          This image has no repo digest on any of your hosts (built locally or loaded with docker
          load), so the server can&apos;t fetch its package list from a registry. The agent will
          send the list for such images; that isn&apos;t available yet.
        </AlertDescription>
      </Alert>
    ) : (
      <Alert>
        <Clock className="size-4" />
        <AlertTitle>No package list yet</AlertTitle>
        <AlertDescription>
          The server hasn&apos;t fetched this image&apos;s package list from its registry yet.
          It&apos;s queued when an agent first reports the image with a repo digest.
        </AlertDescription>
      </Alert>
    );
  }

  if (list.status === "unavailable") {
    const agent = list.reason === SBOM_REASON_PRIVATE;
    return (
      <Alert>
        <PackageX className="size-4" />
        <AlertTitle>
          {agent ? "Private or local image, needs the agent" : "No package list"}
        </AlertTitle>
        <AlertDescription className="flex flex-col gap-1">
          <p>
            Reason: <span className="text-foreground font-medium">{list.reason}</span>
          </p>
          {agent && (
            <p>
              The registry refused an anonymous fetch or isn&apos;t reachable from the server. The
              agent will send package lists for such images; that isn&apos;t available yet.
            </p>
          )}
          {list.lastAttemptAt && <p>Last attempt {formatDateTime(list.lastAttemptAt)}.</p>}
        </AlertDescription>
      </Alert>
    );
  }

  if (list.status === "error") {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="size-4" />
        <AlertTitle>Fetching the package list failed</AlertTitle>
        <AlertDescription className="flex flex-col gap-1">
          <p>{list.reason}</p>
          <p>
            {list.nextAttemptAt
              ? `Retrying at ${formatDateTime(list.nextAttemptAt)}`
              : "Not retried on a timer"}
            {list.attempts > 0 &&
              ` (${list.attempts} failed ${list.attempts === 1 ? "attempt" : "attempts"} so far)`}
            .
          </p>
        </AlertDescription>
      </Alert>
    );
  }

  // ok: the list is there; say what it doesn't cover.
  const why = releaseNotAssessed(list.distro, list.releaseSupported);
  if (why && list.distro) {
    const label = releaseName(list.distro, list.distroVersion, list.release, list.distroName);
    return (
      <Alert>
        <Info className="size-4" />
        <AlertTitle>{RELEASE_NOT_ASSESSED_LABEL[why]}, not assessed</AlertTitle>
        <AlertDescription>
          {releaseNotAssessedText(why, label, list.releaseEol, formatDate)} No vulnerabilities
          listed here doesn&apos;t mean there are none.
        </AlertDescription>
      </Alert>
    );
  }
  if (score && !score.scored) {
    return (
      <Alert>
        <Clock className="size-4" />
        <AlertTitle>Matching in progress</AlertTitle>
        <AlertDescription>
          The package list is being matched against advisories; the score and vulnerabilities appear
          when it&apos;s done.
        </AlertDescription>
      </Alert>
    );
  }
  return null;
}
