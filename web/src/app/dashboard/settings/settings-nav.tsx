"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { settingsSections } from "@/components/layout/settings-sections";
import { cn } from "@/lib/utils";

// A row of links on small screens, a vertical list beside the content from md up.
export function SettingsNav() {
  const pathname = usePathname();
  return (
    <nav
      aria-label="Settings sections"
      className="flex max-w-full gap-1 overflow-x-auto md:flex-col md:overflow-visible"
    >
      {settingsSections.map((s) => {
        const active = pathname === s.url || pathname.startsWith(`${s.url}/`);
        return (
          <Link
            key={s.url}
            href={s.url}
            aria-current={active ? "page" : undefined}
            className={cn(
              "inline-flex h-9 items-center gap-2 rounded-md px-3 text-sm font-medium whitespace-nowrap transition-colors [&_svg]:size-4 [&_svg]:shrink-0",
              active
                ? "bg-muted text-foreground"
                : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
            )}
          >
            <s.icon />
            {s.title}
          </Link>
        );
      })}
    </nav>
  );
}
