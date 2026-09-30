import type { Metadata } from "next";

import { AttentionList } from "@/components/attention/attention-list";
import { PageHeader } from "@/components/layout/page-header";
import { Card, CardContent } from "@/components/ui/card";
import { getAttentionItems } from "@/lib/attention";
import { getEstateHealth } from "@/lib/queries-overview";
import { requireViewer } from "@/lib/viewer";

export const metadata: Metadata = {
  title: "Needs attention",
};

// Every "Needs attention" item, uncapped: the Overview card's "View all".
export default async function AttentionPage() {
  const { workspaceId } = await requireViewer();

  const items = await getAttentionItems(workspaceId, await getEstateHealth(workspaceId));

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <PageHeader
        breadcrumbs={[{ label: "Overview", href: "/dashboard" }, { label: "Needs attention" }]}
        title="Needs attention"
        description="Everything to act on across your hosts, most urgent first."
      />
      <Card>
        <CardContent className="px-3">
          <AttentionList items={items} />
        </CardContent>
      </Card>
    </main>
  );
}
