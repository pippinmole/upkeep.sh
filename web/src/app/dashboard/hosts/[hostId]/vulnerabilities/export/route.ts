// CSV download of a host's vulnerabilities: every finding the
// Vulnerabilities tab would list for the same URL params (status tab,
// search, severity, KEV, fix, sort), across all pages. With no filter that
// is every open finding (or every resolved one with ?status=resolved).
//
// Auth and scoping match requireHost (lib/host-page.ts), answered as
// status codes rather than redirects since this is a download. It only
// reads, so Members may use it (docs/MEMBERS.md):
//   - proxy.ts already sends a request without a session to /login;
//     the viewer is checked again here -> 401.
//   - A user still on a temporary password -> 403.
//   - A host outside the workspace (or that doesn't exist) -> 404, the
//     same answer as the page, so host ids can't be probed.

import type { NextRequest } from "next/server";

import { hostVulnsCsv, hostVulnsCsvFilename } from "@/lib/host-vulns-csv";
import { parseHostVulnFilters, searchParamsOf } from "@/lib/host-vulns-filters";
import { getHostFindingsForExport } from "@/lib/queries-host-vulns-export";
import { getHost } from "@/lib/queries-inventory";
import { getViewer } from "@/lib/viewer";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  ctx: RouteContext<"/dashboard/hosts/[hostId]/vulnerabilities/export">,
) {
  const viewer = await getViewer();
  if (!viewer) return new Response("Unauthorized", { status: 401 });
  if (viewer.mustChangePassword) return new Response("Forbidden", { status: 403 });
  const { workspaceId } = viewer;

  const { hostId } = await ctx.params;
  const host = await getHost(workspaceId, hostId);
  if (!host) return new Response("Not Found", { status: 404 });

  const filters = parseHostVulnFilters(searchParamsOf(request.nextUrl.searchParams));
  const rows = await getHostFindingsForExport(workspaceId, host.id, filters);
  const filename = hostVulnsCsvFilename(host.hostname);

  return new Response(hostVulnsCsv(rows), {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
