"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";

// Link tabs (not Radix Tabs): each tab is its own route, so the URL, back
// button and server rendering all work. Styled after shadcn's TabsList.
export function HostTabs({ hostId, openVulns }: { hostId: string; openVulns: number }) {
  const pathname = usePathname();
  const base = `/dashboard/hosts/${hostId}`;
  const tabs = [
    { href: base, label: "Overview", exact: true },
    { href: `${base}/packages`, label: "Packages" },
    { href: `${base}/vulnerabilities`, label: "Vulnerabilities", count: openVulns },
    { href: `${base}/history`, label: "History" },
    { href: `${base}/services`, label: "Services" },
    { href: `${base}/listeners`, label: "Listeners" },
    { href: `${base}/users`, label: "Users" },
  ];

  return (
    <nav
      aria-label="Host sections"
      className="bg-muted text-muted-foreground inline-flex h-9 w-fit max-w-full items-center overflow-x-auto rounded-lg p-[3px]"
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
            {t.count ? (
              <span className="bg-muted-foreground/15 ml-1.5 rounded px-1.5 text-xs tabular-nums">
                {t.count}
              </span>
            ) : null}
          </Link>
        );
      })}
    </nav>
  );
}
