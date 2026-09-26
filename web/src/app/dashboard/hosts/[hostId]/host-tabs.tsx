"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

// Link tabs (not Radix Tabs): each tab is its own route, so the URL, back
// button and server rendering all work. Styled after shadcn's TabsList.
export function HostTabs({ hostId }: { hostId: string }) {
  const pathname = usePathname();
  const base = `/dashboard/hosts/${hostId}`;
  const tabs = [
    { href: base, label: "Overview", exact: true },
    { href: `${base}/packages`, label: "Packages" },
    { href: `${base}/history`, label: "History" },
  ];

  return (
    <nav
      aria-label="Host sections"
      className="bg-muted text-muted-foreground inline-flex h-9 w-fit items-center rounded-lg p-[3px]"
    >
      {tabs.map((t) => {
        const active = t.exact
          ? pathname === t.href
          : pathname === t.href || pathname.startsWith(`${t.href}/`);
        return (
          <Link
            key={t.href}
            href={t.href}
            aria-current={active ? "page" : undefined}
            className={cn(
              "inline-flex h-full items-center rounded-md px-3 text-sm font-medium whitespace-nowrap transition-colors",
              active ? "bg-background text-foreground shadow-sm" : "hover:text-foreground",
            )}
          >
            {t.label}
          </Link>
        );
      })}
      {/* Vulnerabilities tab: placeholder until vulnerability matching
          (P1b) lands; becomes a Link to `${base}/vulnerabilities` then.
          Deliberately not a link so there is no dead route. */}
      <span
        aria-disabled="true"
        title="Available once vulnerability matching is enabled"
        className="inline-flex h-full cursor-not-allowed items-center gap-1.5 rounded-md px-3 text-sm font-medium whitespace-nowrap opacity-60"
      >
        Vulnerabilities
        <Badge variant="outline" className="px-1.5 py-0 text-[10px] font-normal">
          Soon
        </Badge>
      </span>
    </nav>
  );
}
