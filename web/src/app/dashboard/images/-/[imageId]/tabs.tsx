import {
  tableFacet as facet,
  tableSort as sortOf,
  tableStateFromParams,
} from "@/components/data-table/url-params";
import type { ImageKey } from "@/lib/image-key";
import {
  IMAGE_PACKAGE_SORTS,
  IMAGE_PACKAGE_STATUSES,
  IMAGE_VULN_FIXES,
  IMAGE_VULN_SORTS,
  PACKAGES_TABLE,
  VULNS_TABLE,
} from "@/lib/image-tables";
import { getImageEcosystems, getImagePackages } from "@/lib/queries-image-packages";
import { getImageVulns } from "@/lib/queries-image-vulns";
import type { SearchParams } from "@/lib/search-params";
import { SEVERITIES } from "@/lib/severity";

import { ImagePackagesTable } from "./packages-table";
import { ImageVulnsTable } from "./vulns-table";

// The two tabs' Server Components: URL state -> allowlisted filters ->
// SQL -> one page for the client table.

export async function PackagesTab({
  workspaceId,
  imageKey,
  sp,
}: {
  workspaceId: string;
  imageKey: ImageKey;
  sp: SearchParams;
}) {
  const state = tableStateFromParams(sp, PACKAGES_TABLE);
  const ecosystems = await getImageEcosystems(workspaceId, imageKey);
  const { rows, total } = await getImagePackages(workspaceId, imageKey, {
    q: state.globalFilter || null,
    ecosystems: facet(
      state,
      "ecosystem",
      ecosystems.map((e) => e.ecosystem),
    ),
    statuses: facet(state, "status", IMAGE_PACKAGE_STATUSES),
    sort: sortOf(state, IMAGE_PACKAGE_SORTS, "status"),
    page: state.pagination.pageIndex + 1,
    pageSize: state.pagination.pageSize,
  });
  return <ImagePackagesTable rows={rows} total={total} state={state} ecosystems={ecosystems} />;
}

export async function VulnsTab({
  workspaceId,
  imageKey,
  sp,
  scored,
  notAssessed,
}: {
  workspaceId: string;
  imageKey: ImageKey;
  sp: SearchParams;
  scored: boolean; // the rows exist once the list's score is current
  notAssessed: number;
}) {
  const state = tableStateFromParams(sp, VULNS_TABLE);
  const severities = facet(state, "severity", SEVERITIES);
  const kev = facet(state, "kev", ["1"]) !== null;
  const fix = facet(state, "fix", IMAGE_VULN_FIXES);
  const { rows, total } = await getImageVulns(workspaceId, imageKey, {
    q: state.globalFilter || null,
    severities,
    kev,
    fix,
    sort: sortOf(state, IMAGE_VULN_SORTS, "severity"),
    page: state.pagination.pageIndex + 1,
    pageSize: state.pagination.pageSize,
  });
  const filtered = state.globalFilter || severities || kev || fix;
  const empty = !scored
    ? "Matching in progress: this list's vulnerabilities appear once it is scored."
    : filtered
      ? "No vulnerabilities match these filters."
      : notAssessed > 0
        ? `No known vulnerabilities in the assessed packages (${notAssessed} not assessed).`
        : "No known vulnerabilities.";
  return <ImageVulnsTable rows={rows} total={total} state={state} emptyMessage={empty} />;
}
