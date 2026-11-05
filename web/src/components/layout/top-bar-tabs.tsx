"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { cn } from "@/lib/utils";

import { isTabActive, tabs } from "./nav-config";

// How far the edge fade reaches into the row.
const FADE = "1.5rem";

type Edges = { left: boolean; right: boolean };

// A fade on each edge that has tabs scrolled past it, so a row cut short
// (a narrow md bar, or the phone row) shows there is more to scroll to.
function fadeMask({ left, right }: Edges): string | undefined {
  if (!left && !right) return undefined;
  const start = left ? `transparent, #000 ${FADE}` : "#000";
  const end = right ? `#000 calc(100% - ${FADE}), transparent` : "#000";
  return `linear-gradient(to right, ${start}, ${end})`;
}

// The top bar's tabs. From md up they sit in the bar between the workspace
// and the actions; below md the bar wraps them onto a second row that
// scrolls sideways, with the active tab scrolled into view. Either way the
// row scrolls when it is too narrow, with a fade on the cut-off side(s).
export function TopBarTabs({ className }: { className?: string }) {
  const pathname = usePathname();
  const navRef = useRef<HTMLElement>(null);
  const activeRef = useRef<HTMLAnchorElement>(null);
  const [edges, setEdges] = useState<Edges>({ left: false, right: false });

  useEffect(() => {
    const nav = navRef.current;
    if (!nav) return;
    const update = () => {
      const left = nav.scrollLeft > 1;
      const right = nav.scrollLeft + nav.clientWidth < nav.scrollWidth - 1;
      setEdges((prev) => (prev.left === left && prev.right === right ? prev : { left, right }));
    };
    update();
    nav.addEventListener("scroll", update, { passive: true });
    const observer = new ResizeObserver(update);
    observer.observe(nav);
    return () => {
      nav.removeEventListener("scroll", update);
      observer.disconnect();
    };
  }, []);

  useEffect(() => {
    const nav = navRef.current;
    const active = activeRef.current;
    if (!nav || !active || nav.scrollWidth <= nav.clientWidth) {
      return;
    }
    // Scroll the row only, never the page (scrollIntoView could).
    nav.scrollLeft = active.offsetLeft - (nav.clientWidth - active.offsetWidth) / 2;
  }, [pathname]);

  const mask = fadeMask(edges);

  return (
    <nav
      ref={navRef}
      aria-label="Main"
      style={mask ? { maskImage: mask, WebkitMaskImage: mask } : undefined}
      className={cn(
        // scroll-px keeps a tab reached by keyboard clear of the fade.
        "relative flex scroll-px-6 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden",
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
              "focus-visible:ring-ring inline-flex h-full shrink-0 items-center px-3 text-sm font-medium whitespace-nowrap transition-colors focus-visible:ring-2 focus-visible:outline-none focus-visible:ring-inset motion-reduce:transition-none",
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
