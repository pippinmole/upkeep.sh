// CSV download of a host's vulnerabilities: every finding the
// Vulnerabilities tab would list for the same URL params (status tab,
// search, severity, KEV, fix, sort), across all pages. With no filter that
// is every open finding (or every resolved one with ?status=resolved).
//
// Auth and ownership match requireHost (lib/host-page.ts), answered as
// status codes rather than redirects since this is a download:
//   - proxy.ts already sends a request without a session to /login;
//     auth() is checked again here -> 401.
//   - A host that isn't the user's (or doesn't exist) -> 404, the same
//     answer as the page, so host ids can't be probed.

import type { NextRequest } from "next/server";

import { auth } from "@/lib/auth";
import { hostVulnsCsv, hostVulnsCsvFilename } from "@/lib/host-vulns-csv";
import { parseHostVulnFilters, searchParamsOf } from "@/lib/host-vulns-filters";
import { getHostFindingsForExport } from "@/lib/queries-host-vulns-export";
import { getHost } from "@/lib/queries-inventory";

export const dynamic = "force-dynamic";

export async function GET(
  request: NextRequest,
  ctx: RouteContext<"/dashboard/hosts/[hostId]/vulnerabilities/export">,
) {
  const session = await auth();
  const userId = session?.user?.id;
  if (!userId) return new Response("Unauthorized", { status: 401 });

  const { hostId } = await ctx.params;
  const host = await getHost(userId, hostId);
  if (!host) return new Response("Not Found", { status: 404 });

  const filters = parseHostVulnFilters(searchParamsOf(request.nextUrl.searchParams));
  const rows = await getHostFindingsForExport(userId, host.id, filters);
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
