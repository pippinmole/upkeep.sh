import { Info } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";

import { CopyButton } from "@/components/copy-button";
import { API_TOKEN_PREFIX, appBaseUrl } from "@/lib/auth";
import { requireViewer } from "@/lib/viewer";

import { API_TOKENS_URL, CONNECTED_APPS_URL } from "./links";

export const metadata: Metadata = { title: "Integrations" };

const linkClass = "text-foreground font-medium underline underline-offset-4";

function Command({ command }: { command: string }) {
  return (
    <div className="relative mt-2">
      <pre className="bg-muted text-foreground overflow-x-auto rounded-md border p-3 pr-12 text-xs">
        {command}
      </pre>
      <CopyButton className="absolute top-2 right-2 h-7 w-7" text={command} />
    </div>
  );
}

// Connect: how to add this install to Claude Code (docs/MCP.md#stories),
// with a browser sign-in, or with an API token for headless use. The URL is
// BETTER_AUTH_URL, the address users sign in at, so the commands are right
// for this install as it stands.
export default async function ConnectPage() {
  await requireViewer();
  const url = `${appBaseUrl()}/api/mcp`;
  const command = `claude mcp add --transport http upkeep ${url}`;
  const headless = `${command} --header "Authorization: Bearer ${API_TOKEN_PREFIX}…"`;

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <section className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold">Connect Claude Code</h3>
        <ol className="text-muted-foreground flex list-decimal flex-col gap-3 pl-5 text-sm">
          <li className="pl-1">
            <span>Add this install as an MCP server:</span>
            <Command command={command} />
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

      <section className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold">Without a browser</h3>
        <p className="text-muted-foreground text-sm">
          For <code className="text-foreground">claude -p</code> in cron or CI, the Agent SDK, or a
          machine without a browser: create a token under{" "}
          <Link href={API_TOKENS_URL} className={linkClass}>
            API tokens
          </Link>{" "}
          and pass it as a header instead of signing in:
        </p>
        <Command command={headless} />
        <p className="text-muted-foreground text-sm">
          Replace <code className="text-foreground">{API_TOKEN_PREFIX}…</code> with the token. It
          reads the workspace with your permissions until it expires or you revoke it.
        </p>
      </section>

      <div className="border-info/40 bg-info/10 flex gap-3 rounded-lg border px-4 py-3 text-sm">
        <Info className="text-info-fg mt-0.5 size-4 shrink-0" aria-hidden />
        <p>
          Signing in needs outbound HTTPS to <code>claude.ai</code>: this install fetches Claude
          Code&apos;s client metadata from there (and again about once an hour). An install that
          can&apos;t reach the internet can connect Claude Code with an API token instead.
        </p>
      </div>
    </div>
  );
}
