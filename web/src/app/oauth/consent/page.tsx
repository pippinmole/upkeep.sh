import { verifyOAuthQueryParams } from "@better-auth/oauth-provider";
import { Check } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { LogOutButton } from "@/components/layout/log-out-button";
import { pool } from "@/lib/db";
import { describeScope } from "@/lib/mcp/scopes";
import { oauthQueryFrom, type PageSearchParams } from "@/lib/oauth-query";
import { getViewer } from "@/lib/viewer";

import { AuthShell } from "../../login/auth-shell";
import { ConsentForm } from "./consent-form";

export const metadata: Metadata = { title: "Connect an app" };

export const dynamic = "force-dynamic";

// The OAuth consent page (docs/MCP.md#oauth-interactive-clients): Better
// Auth's OAuth provider sends the browser here, with the authorization
// request as signed query parameters, when a client (Claude Code) asks for
// access the user hasn't granted yet. Allow / Deny go to decideConsent.

function hostOf(url: string | null | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).host;
  } catch {
    return null;
  }
}

function Expired() {
  return (
    <AuthShell
      title="Request expired"
      description="This connection request is no longer valid."
      footer={<LogOutButton />}
    >
      <p className="text-muted-foreground text-sm">
        Start the connection again from your app (in Claude Code, run <code>/mcp</code> and pick the
        server).
      </p>
    </AuthShell>
  );
}

export default async function ConsentPage({
  searchParams,
}: {
  searchParams: Promise<PageSearchParams>;
}) {
  const oauthQuery = oauthQueryFrom(await searchParams);
  const viewer = await getViewer();
  if (!viewer) redirect(oauthQuery ? `/login?${oauthQuery}` : "/login");
  if (
    !oauthQuery ||
    !(await verifyOAuthQueryParams(oauthQuery, process.env.BETTER_AUTH_SECRET ?? ""))
  ) {
    return <Expired />;
  }
  // A temporary password is replaced first; the change-password page comes
  // back here afterwards.
  if (viewer.mustChangePassword) {
    redirect(`/change-password?next=${encodeURIComponent(`/oauth/consent?${oauthQuery}`)}`);
  }

  const q = new URLSearchParams(oauthQuery);
  const clientId = q.get("client_id") ?? "";
  const { rows } = await pool.query<{ name: string | null; uri: string | null }>(
    `SELECT name, uri FROM oauth_clients WHERE client_id = $1 AND NOT coalesce(disabled, false)`,
    [clientId],
  );
  const client = rows[0];
  if (!client) return <Expired />;
  // Where the client's identity comes from: the host of its metadata
  // document (CIMD client ids are URLs), else of its redirect URI.
  const from = hostOf(clientId) ?? hostOf(q.get("redirect_uri"));
  const name = client.name ?? "An app";
  const scopes = (q.get("scope") ?? "").split(" ").filter(Boolean);

  return (
    <AuthShell
      title={`Connect ${name}?`}
      description={`${name}${from ? ` (${from})` : ""} wants to access upkeep.sh as ${
        viewer.username ?? viewer.email
      }.`}
      footer={<LogOutButton />}
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <p className="text-sm font-medium">It will be able to:</p>
          <ul className="flex flex-col gap-1.5">
            {scopes.map((s) => (
              <li key={s} className="flex items-start gap-2 text-sm">
                <Check className="text-primary mt-0.5 size-4 shrink-0" aria-hidden />
                {describeScope(s)}
              </li>
            ))}
          </ul>
          <p className="text-muted-foreground text-xs">
            Read-only: it can't change anything in upkeep.sh. You can revoke access at any time.
          </p>
        </div>
        <ConsentForm oauthQuery={oauthQuery} />
      </div>
    </AuthShell>
  );
}
