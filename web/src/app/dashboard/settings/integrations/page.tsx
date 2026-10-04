import { Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { CopyButton } from "@/components/copy-button";
import { appBaseUrl } from "@/lib/auth";
import { requireViewer } from "@/lib/viewer";

import { INTEGRATION_TABS } from "./links";

export const metadata: Metadata = { title: "Integrations" };

const linkClass = "text-foreground font-medium underline underline-offset-4";
const CONNECTED_APPS_URL = INTEGRATION_TABS[1].href;

// Connect: how to add this install to Claude Code (docs/MCP.md#stories).
// The URL is BETTER_AUTH_URL, the address users sign in at, so the command
// is right for this install as it stands.
export default async function ConnectPage() {
  await requireViewer();
  const command = `claude mcp add --transport http upkeep ${appBaseUrl()}/api/mcp`;

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <section className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold">Connect Claude Code</h3>
        <ol className="text-muted-foreground flex list-decimal flex-col gap-3 pl-5 text-sm">
          <li className="pl-1">
            <span>Add this install as an MCP server:</span>
            <div className="relative mt-2">
              <pre className="bg-muted text-foreground overflow-x-auto rounded-md border p-3 pr-12 text-xs">
                {command}
              </pre>
              <CopyButton className="absolute top-2 right-2 h-7 w-7" text={command} />
            </div>
          </li>
          <li className="pl-1">
            In Claude Code, run <code className="text-foreground">/mcp</code>, pick{" "}
            <code className="text-foreground">upkeep</code> and choose{" "}
            <span className="text-foreground font-medium">Authenticate</span>.
          </li>
          <li className="pl-1">
            Your browser opens on upkeep.sh. Sign in if asked, check what Claude Code will be able
            to do, and choose <span className="text-foreground font-medium">Allow</span>.
          </li>
          <li className="pl-1">
            Back in Claude Code, ask something like &ldquo;summarize my upkeep.sh workspace&rdquo;.
          </li>
        </ol>
        <p className="text-muted-foreground text-sm">
          Claude Code reads the workspace with your permissions and can&apos;t change anything. It
          then appears under{" "}
          <Link href={CONNECTED_APPS_URL} className={linkClass}>
            Connected apps
          </Link>
          , where you can revoke it.
        </p>
      </section>

      <div className="border-info/40 bg-info/10 flex gap-3 rounded-lg border px-4 py-3 text-sm">
        <Info className="text-info-fg mt-0.5 size-4 shrink-0" aria-hidden />
        <p>
          This install needs outbound HTTPS to <code>claude.ai</code>: when you sign in, it fetches
          Claude Code&apos;s client metadata from there (and again about once an hour). An install
          that can&apos;t reach the internet can&apos;t connect Claude Code this way yet.
        </p>
      </div>
    </div>
  );
}
