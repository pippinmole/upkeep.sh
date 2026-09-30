import { CheckCircle2, ChevronRight } from "lucide-react";
import Link from "next/link";

import type { AttentionItem } from "@/lib/attention/types";

import { AttentionIcon } from "./attention-icon";

// Rows of "Needs attention" items, each linking to where it's fixed: the
// Overview card shows the top few, /dashboard/attention all of them.
export function AttentionList({ items }: { items: AttentionItem[] }) {
  if (items.length === 0) return <AllClear />;
  return (
    <ul className="flex flex-col">
      {items.map((it) => (
        <li key={it.key}>
          <AttentionRow item={it} />
        </li>
      ))}
    </ul>
  );
}

function AttentionRow({ item: it }: { item: AttentionItem }) {
  return (
    <Link
      href={it.href}
      className="hover:bg-accent/50 focus-visible:ring-ring flex items-center gap-3 rounded-md px-3 py-2.5 transition-colors focus-visible:ring-2 focus-visible:outline-hidden"
    >
      <AttentionIcon icon={it.icon} tone={it.tone} />
      <span className="flex min-w-0 flex-1 flex-col">
        <span className="text-sm font-medium">{it.title}</span>
        {it.subject && (
          <span className="truncate text-sm" title={it.subject}>
            {it.subject}
          </span>
        )}
        <span className="text-muted-foreground text-xs">{it.why}</span>
      </span>
      {it.count !== null && (
        <span className="text-lg font-semibold tabular-nums">
          {it.count.toLocaleString("en-US")}
        </span>
      )}
      <ChevronRight className="text-muted-foreground size-4 shrink-0" aria-hidden />
    </Link>
  );
}

function AllClear() {
  return (
    <div className="flex items-center gap-3 rounded-md px-3 py-2.5">
      <span className="bg-success/10 text-success-fg flex size-8 shrink-0 items-center justify-center rounded-md">
        <CheckCircle2 className="size-4" aria-hidden />
      </span>
      <div>
        <p className="text-sm font-medium">All clear</p>
        <p className="text-muted-foreground text-sm">
          No exploited or fixable critical vulnerabilities, silent hosts, pending reboots, failing
          collectors or end-of-life releases.
        </p>
      </div>
    </div>
  );
}
