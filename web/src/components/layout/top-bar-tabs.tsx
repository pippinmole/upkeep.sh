"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef } from "react";

import { cn } from "@/lib/utils";

import { isTabActive, tabs } from "./nav-config";

// The top bar's tabs. From md up they sit in the bar between the workspace
// and the actions; below md the bar wraps them onto a second row that
// scrolls sideways, with the active tab scrolled into view.
export function TopBarTabs({ className }: { className?: string }) {
  const pathname = usePathname();
  const navRef = useRef<HTMLElement>(null);
  const activeRef = useRef<HTMLAnchorElement>(null);

  useEffect(() => {
    const nav = navRef.current;
    const active = activeRef.current;
    if (!nav || !active || nav.scrollWidth <= nav.clientWidth) {
      return;
    }
    // Scroll the row only, never the page (scrollIntoView could).
    nav.scrollLeft = active.offsetLeft - (nav.clientWidth - active.offsetWidth) / 2;
  }, [pathname]);

  return (
    <nav
      ref={navRef}
      aria-label="Main"
      className={cn(
        "relative flex overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden",
        className,
      )}
    >
      {tabs.map((tab) => {
        const active = isTabActive(pathname, tab);
        return (
          <Link
            key={tab.url}
            ref={active ? activeRef : undefined}
            href={tab.url}
            aria-current={active ? "page" : undefined}
            className={cn(
              "focus-visible:ring-ring inline-flex h-full shrink-0 items-center px-3 text-sm font-medium whitespace-nowrap transition-colors focus-visible:ring-2 focus-visible:outline-none focus-visible:ring-inset",
              active
                ? "text-topbar-foreground shadow-[inset_0_-2px_0_var(--brand)]"
                : "text-topbar-muted hover:text-topbar-foreground",
            )}
          >
            {tab.title}
          </Link>
        );
      })}
    </nav>
  );
}
