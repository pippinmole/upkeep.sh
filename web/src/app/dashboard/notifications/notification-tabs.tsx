"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";

const BASE = "/dashboard/notifications";
const TABS = [
  { href: BASE, label: "Rules" },
  { href: `${BASE}/channels`, label: "Channels" },
  { href: `${BASE}/log`, label: "Delivery log" },
];

// Link tabs, same pattern as the host tabs.
export function NotificationTabs() {
  const pathname = usePathname();
  return (
    <nav
      aria-label="Notification sections"
      className="bg-muted text-muted-foreground inline-flex h-9 w-fit max-w-full items-center overflow-x-auto rounded-lg p-[3px]"
    >
      {TABS.map((t) => {
        const active = pathname === t.href;
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
    </nav>
  );
}
