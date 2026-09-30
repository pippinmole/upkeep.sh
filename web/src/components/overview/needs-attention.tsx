import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { AttentionList } from "@/components/attention/attention-list";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { capItems } from "@/lib/attention/rank";
import type { AttentionItem } from "@/lib/attention/types";
import { cn } from "@/lib/utils";

// The Overview's ranked "what to do now" list (docs/NEEDS_ATTENTION.md):
// the most urgent items, capped, with a link to the full list.

export const OVERVIEW_MAX_ITEMS = 6;

export function NeedsAttention({
  items,
  className,
}: {
  items: AttentionItem[];
  className?: string;
}) {
  const { shown, hidden } = capItems(items, OVERVIEW_MAX_ITEMS);
  return (
    <Card className={cn("gap-3", className)}>
      <CardHeader>
        <CardTitle>Needs attention</CardTitle>
        <CardDescription>Most urgent first.</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-1 px-3">
        <AttentionList items={shown} />
        {hidden > 0 && (
          <Link
            href="/dashboard/attention"
            className="text-muted-foreground hover:text-foreground flex items-center gap-1 self-start px-3 py-1 text-sm hover:underline"
          >
            View all {items.length} ({hidden} more)
            <ArrowRight className="size-3.5" aria-hidden />
          </Link>
        )}
      </CardContent>
    </Card>
  );
}
