"use client";

import { Container } from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";

// Link tabs (not Radix Tabs): each tab is its own route, so the URL, back
// button and server rendering all work. Ordered by task: triage first,
// inventory next, history last. Counts are only those the layout already
// has (null = not known, no pill). Vulnerabilities has two pills, host
// package and container image findings, never summed (DOMAIN_MODEL.md §3.5).
export function HostTabs({
  hostId,
  openVulns,
  openImageVulns,
  packages,
}: {
  hostId: string;
  openVulns: number;
  openImageVulns: number;
  packages: number | null;
}) {
  const pathname = usePathname();
  const base = `/dashboard/hosts/${hostId}`;
  const tabs: {
    href: string;
    label: string;
    exact?: boolean;
    count?: number | null;
    imageCount?: number;
  }[] = [
    { href: base, label: "Overview", exact: true },
    {
      href: `${base}/vulnerabilities`,
      label: "Vulnerabilities",
      count: openVulns,
      imageCount: openImageVulns,
    },
    { href: `${base}/packages`, label: "Packages", count: packages },
    { href: `${base}/listeners`, label: "Listeners" },
    { href: `${base}/services`, label: "Services" },
    { href: `${base}/users`, label: "Users" },
    // Always shown: on hosts without Docker data the tab explains why
    // (remote host, collection not enabled, engine unreachable).
    { href: `${base}/containers`, label: "Containers" },
    { href: `${base}/images`, label: "Images" },
    { href: `${base}/history`, label: "History" },
  ];

  return (
    <div className="border-b">
      {/* Scrolls sideways on narrow screens; the right edge fades out so a
          cut-off tab reads as "more this way". The end padding lets the
          last tab scroll clear of the fade. */}
      <nav
        aria-label="Host sections"
        className="-mb-px flex overflow-x-auto pr-8 [mask-image:linear-gradient(to_right,black_calc(100%-2rem),transparent)] [scrollbar-width:none] lg:pr-0 lg:[mask-image:none]"
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
                "inline-flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors",
                active
                  ? "border-primary text-foreground"
                  : "text-muted-foreground hover:border-border hover:text-foreground border-transparent",
              )}
            >
              {t.label}
              {t.count != null && t.count > 0 && (
                <span
                  className="bg-muted text-muted-foreground rounded px-1.5 text-xs tabular-nums"
                  title={t.imageCount !== undefined ? "Open in host packages" : undefined}
                >
                  {t.count.toLocaleString("en-GB")}
                </span>
              )}
              {t.imageCount !== undefined && t.imageCount > 0 && (
                <span
                  className="bg-muted text-muted-foreground inline-flex items-center gap-0.5 rounded px-1.5 text-xs tabular-nums"
                  title="Open in container images"
                >
                  <Container className="size-3" aria-label="Container images" />
                  {t.imageCount.toLocaleString("en-GB")}
                </span>
              )}
            </Link>
          );
        })}
      </nav>
    </div>
  );
}
