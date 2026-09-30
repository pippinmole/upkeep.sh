// Global search for the command menu: GET /api/search?q=<text>.
//
// Read-only, so any signed-in viewer (member or administrator) may call it;
// results are scoped to the workspace (docs/MEMBERS.md). proxy.ts only
// guards /dashboard, so this handler checks the session itself:
//   not signed in (or disabled) -> 401, still on a temporary password -> 403.
// Queries shorter than MIN_QUERY_LENGTH return empty groups without
// touching the database.

import { runSearch } from "@/lib/search/run";
import { getViewer } from "@/lib/viewer";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const json = (body: unknown, status = 200) =>
  Response.json(body, { status, headers: { "Cache-Control": "no-store" } });

export async function GET(request: Request) {
  const viewer = await getViewer();
  if (!viewer) return json({ error: "You are not signed in." }, 401);
  if (viewer.mustChangePassword) return json({ error: "Choose a new password first." }, 403);

  const q = new URL(request.url).searchParams.get("q") ?? "";
  try {
    return json(await runSearch(viewer.workspaceId, q));
  } catch (err) {
    console.error("search failed", err);
    return json({ error: "Search failed." }, 500);
  }
}
