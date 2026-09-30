"use client";

import {
  ArrowRight,
  BellPlus,
  CalendarPlus,
  Keyboard,
  Laptop,
  Moon,
  PanelLeft,
  Plus,
  Search as SearchIcon,
  Send,
  ShieldAlert,
  Sun,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import * as React from "react";

import { visibleNavConfig } from "@/components/layout/nav-config";
import { settingsSections } from "@/components/layout/settings-sections";
import { NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSidebar } from "@/components/ui/sidebar";
import { vulnHref } from "@/components/vuln/links";

import { Shortcut } from "./search";
import { useSearch } from "./search-provider";
import { useViewer } from "./viewer-context";

// Advisory id prefixes that open a vulnerability page directly.
const VULN_ID = /^(CVE|GHSA|USN|DSA|DLA|ALSA|RHSA)-/i;

// Nothing here takes a query param yet (?add=1 and the like), so the
// actions open the page that holds the button.
const ACTIONS = [
  {
    title: "Add host",
    url: "/dashboard/hosts",
    icon: Plus,
    keywords: ["enroll", "agent", "install"],
  },
  { title: "Add channel", url: NOTIFICATION_SETTINGS_URL, icon: Send, keywords: ["notifications"] },
  { title: "New alert rule", url: "/dashboard/alerts", icon: BellPlus, keywords: ["notify"] },
  {
    title: "New report schedule",
    url: "/dashboard/reports",
    icon: CalendarPlus,
    keywords: ["weekly"],
  },
];

// Rendered by the dashboard layout, inside SidebarProvider.
export function CommandMenu({ hasSwarm }: { hasSwarm: boolean }) {
  const router = useRouter();
  const { setTheme } = useTheme();
  const { toggleSidebar } = useSidebar();
  const { open, setOpen } = useSearch();
  const [query, setQuery] = React.useState("");
  // The actions all lead to write controls, which members don't get.
  const { isAdmin } = useViewer();

  const onOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) setQuery("");
  };
  const run = (command: () => unknown) => {
    onOpenChange(false);
    command();
  };
  const go = (url: string) => run(() => router.push(url));

  const q = query.trim();
  // Upper-case the prefix only: GHSA ids keep their lower-case tail.
  const vulnKey = VULN_ID.test(q) ? q.replace(VULN_ID, (m) => m.toUpperCase()) : null;
  const groups = [
    ...visibleNavConfig(hasSwarm).map((g) => ({ heading: g.title ?? "Pages", items: g.items })),
    { heading: "Settings", items: settingsSections },
  ];

  return (
    <CommandDialog modal open={open} onOpenChange={onOpenChange}>
      <CommandInput
        placeholder="Go to a page, CVE or package…"
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <ScrollArea type="hover" className="h-72 pr-1">
          <CommandEmpty>No results found.</CommandEmpty>
          {q && (
            <CommandGroup heading="Search">
              {vulnKey && (
                <CommandItem forceMount value={`vuln ${q}`} onSelect={() => go(vulnHref(vulnKey))}>
                  <ShieldAlert />
                  <span>
                    Go to vulnerability <span className="font-mono">{vulnKey}</span>
                  </span>
                </CommandItem>
              )}
              <CommandItem
                forceMount
                value={`packages ${q}`}
                onSelect={() => go(`/dashboard/packages?q=${encodeURIComponent(q)}`)}
              >
                <SearchIcon />
                <span>
                  Search packages for <span className="font-medium">“{q}”</span>
                </span>
              </CommandItem>
            </CommandGroup>
          )}
          {groups.map((group) => (
            <CommandGroup key={group.heading} heading={group.heading}>
              {group.items.map((item) => (
                <CommandItem
                  key={item.url}
                  value={item.title}
                  keywords={item.keywords}
                  onSelect={() => go(item.url)}
                >
                  <div className="mr-2 flex h-4 w-4 items-center justify-center">
                    <ArrowRight className="text-muted-foreground/80 size-2" />
                  </div>
                  {item.title}
                </CommandItem>
              ))}
            </CommandGroup>
          ))}
          {isAdmin && <CommandSeparator />}
          <CommandGroup heading="Actions" hidden={!isAdmin}>
            {(isAdmin ? ACTIONS : []).map((a) => (
              <CommandItem
                key={a.title}
                value={a.title}
                keywords={a.keywords}
                onSelect={() => go(a.url)}
              >
                <a.icon />
                <span>{a.title}</span>
              </CommandItem>
            ))}
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="Theme">
            <CommandItem onSelect={() => run(() => setTheme("light"))}>
              <Sun /> <span>Light</span>
            </CommandItem>
            <CommandItem onSelect={() => run(() => setTheme("dark"))}>
              <Moon className="scale-90" />
              <span>Dark</span>
            </CommandItem>
            <CommandItem onSelect={() => run(() => setTheme("system"))}>
              <Laptop />
              <span>System</span>
            </CommandItem>
          </CommandGroup>
          <CommandSeparator />
          <CommandGroup heading="Keyboard shortcuts">
            <CommandItem
              value="Toggle sidebar"
              keywords={["shortcut"]}
              onSelect={() => run(toggleSidebar)}
            >
              <PanelLeft />
              <span>Toggle sidebar</span>
              <Shortcut keyName="B" className="ml-auto" />
            </CommandItem>
            <CommandItem
              value="Command menu"
              keywords={["shortcut", "search"]}
              onSelect={() => onOpenChange(false)}
            >
              <Keyboard />
              <span>Open this menu</span>
              <Shortcut keyName="K" className="ml-auto" />
            </CommandItem>
          </CommandGroup>
        </ScrollArea>
      </CommandList>
    </CommandDialog>
  );
}
