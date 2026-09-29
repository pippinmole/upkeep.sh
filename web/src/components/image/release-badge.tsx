import { Badge } from "@/components/ui/badge";
import {
  RELEASE_NOT_ASSESSED_LABEL,
  releaseNotAssessedText,
  type ImageScoreState,
} from "@/lib/image-score";
import { formatDate } from "@/lib/time";

// An image whose base OS release isn't assessed (out of support, not
// recognised, or a distro whose advisories aren't imported): a dashed
// badge, never the green "no known vulnerabilities", with the release and
// its end-of-life date underneath. Shared by score cells and the image
// header. No hooks.

type State = Extract<ImageScoreState, { kind: "release_not_assessed" }>;

export function ReleaseNotAssessedBadge({ st }: { st: State }) {
  return (
    <div
      className="flex cursor-help flex-col items-start gap-0.5"
      title={`${releaseNotAssessedText(st.why, st.label, st.eol, formatDate)} No known vulnerabilities means nothing here.`}
    >
      <Badge variant="dashed" className="font-normal whitespace-nowrap">
        {RELEASE_NOT_ASSESSED_LABEL[st.why]}
      </Badge>
      <span className="text-muted-foreground text-xs whitespace-nowrap">
        {st.label}
        {st.eol ? ` · EOL ${formatDate(st.eol)}` : " · not assessed"}
      </span>
    </div>
  );
}
