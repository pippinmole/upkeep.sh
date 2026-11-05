"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { settingsSections } from "@/components/layout/settings-sections";
import { cn } from "@/lib/utils";

function isActive(pathname: string, s: { url: string }) {
  return pathname === s.url || pathname.startsWith(`${s.url}/`);
}

// From md up: a column of links beside the content, sticky under the top
// bar. Below md: a row of links above it.
export function SettingsNav() {
  const pathname = usePathname();
  return (
    <>
      <nav
        aria-label="Settings sections"
        className="flex max-w-full gap-1 overflow-x-auto md:hidden"
      >
        {settingsSections.map((s) => {
          const active = isActive(pathname, s);
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

      <aside className="hidden w-48 shrink-0 md:block">
        <nav aria-label="Settings sections" className="sticky top-16 pt-0.5">
          <ul className="-ml-2 flex flex-col gap-1">
            {settingsSections.map((s) => {
              const active = isActive(pathname, s);
              return (
                <li key={s.url}>
                  <Link
                    href={s.url}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "focus-visible:ring-ring flex h-8 items-center gap-2 rounded-md p-2 text-sm transition-colors focus-visible:ring-2 focus-visible:outline-none [&_svg]:size-4 [&_svg]:shrink-0",
                      active
                        ? "bg-muted text-foreground font-medium"
                        : "hover:bg-muted/60 hover:text-foreground",
                    )}
                  >
                    <s.icon />
                    <span className="truncate">{s.title}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>
      </aside>
    </>
  );
}
