import { SectionHeading } from "@/components/layout/page-header";

import { IntegrationTabs } from "./integration-tabs";

// Settings > Integrations (docs/MCP.md#settings--integrations): connect an
// MCP client such as Claude Code to this install, see and revoke the apps
// that are connected, create API tokens for headless clients, and see what
// they called. Open to members and administrators; each page checks the
// viewer itself.
export default function IntegrationsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-4">
      <SectionHeading description="Let AI assistants such as Claude Code read this workspace over MCP, with your permissions.">
        Integrations
      </SectionHeading>
      <IntegrationTabs />
      <div className="mt-2">{children}</div>
    </div>
  );
}
