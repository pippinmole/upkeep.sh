import { ExternalLink } from "lucide-react";
import Link from "next/link";

import { advisoryUrl } from "@/lib/severity";
import { cn } from "@/lib/utils";

export function vulnHref(vulnKey: string): string {
  return `/dashboard/vulnerabilities/${encodeURIComponent(vulnKey)}`;
}

// Advisory ids as external links to the Debian / Ubuntu trackers.
export function AdvisoryLinks({ ids, className }: { ids: string[]; className?: string }) {
  if (ids.length === 0) return null;
  return (
    <span className={cn("inline-flex flex-wrap gap-x-2 gap-y-0.5 text-xs", className)}>
      {ids.map((id) => {
        const url = advisoryUrl(id);
        return url ? (
          <a
            key={id}
            href={url}
            target="_blank"
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground inline-flex items-center gap-0.5 underline-offset-4 hover:underline"
          >
            {id}
            <ExternalLink className="size-3" />
          </a>
        ) : (
          <span key={id} className="text-muted-foreground">
            {id}
          </span>
        );
      })}
    </span>
  );
}

// Segmented link control (Open / Resolved etc.), styled like HostTabs.
export function SegmentedLinks({
  items,
  label,
}: {
  label: string;
  items: { href: string; label: React.ReactNode; active: boolean }[];
}) {
  return (
    <nav
      aria-label={label}
      className="bg-muted text-muted-foreground inline-flex h-9 w-fit items-center rounded-lg p-[3px]"
    >
      {items.map((it) => (
        <Link
          key={it.href}
          href={it.href}
          aria-current={it.active ? "page" : undefined}
          className={cn(
            "inline-flex h-full items-center rounded-md px-3 text-sm font-medium whitespace-nowrap transition-colors",
            it.active ? "bg-background text-foreground shadow-sm" : "hover:text-foreground",
          )}
        >
          {it.label}
        </Link>
      ))}
    </nav>
  );
}
