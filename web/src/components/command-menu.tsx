"use client";

import { defaultFilter } from "cmdk";
import {
  ArrowRight,
  BellPlus,
  CalendarPlus,
  Keyboard,
  Laptop,
  Moon,
  PanelLeft,
  Plus,
  Send,
  Sun,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import * as React from "react";

import {
  SearchResultGroups,
  firstResultValue,
  hasResults,
} from "@/components/global-search/search-results";
import { SearchStatus } from "@/components/global-search/search-status";
import { ShowAllGroup } from "@/components/global-search/show-all-group";
import { useGlobalSearch } from "@/components/global-search/use-global-search";
import { visibleNavConfig } from "@/components/layout/nav-config";
import { settingsSections } from "@/components/layout/settings-sections";
import { NOTIFICATION_SETTINGS_URL } from "@/components/notifications/links";
import {
  CommandDialog,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useSidebar } from "@/components/ui/sidebar";
import { normalizeQuery } from "@/lib/search/query";

import { Shortcut } from "./search";
import { useSearch } from "./search-provider";
import { useViewer } from "./viewer-context";

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
  {
    title: "New alert rule",
    url: "/dashboard/settings/alert-rules",
    icon: BellPlus,
    keywords: ["notify"],
  },
  {
    title: "New report schedule",
    url: "/dashboard/reports",
    icon: CalendarPlus,
    keywords: ["weekly"],
  },
];

type Command = { title: string; keywords?: string[] };

// The menu filters its own items (the Command has shouldFilter={false},
// since data results come from the server already matched), with cmdk's
// own fuzzy scoring so pages match as they did before.
function matches(c: Command, q: string): boolean {
  return !q || defaultFilter(c.title, q, c.keywords) > 0;
}

// Rendered by the dashboard layout, inside SidebarProvider.
export function CommandMenu({ hasSwarm }: { hasSwarm: boolean }) {
  const router = useRouter();
  const { setTheme } = useTheme();
  const { toggleSidebar } = useSidebar();
  const { open, setOpen } = useSearch();
  const [query, setQuery] = React.useState("");
  // The actions all lead to write controls, which members don't get.
  const { isAdmin } = useViewer();
  const search = useGlobalSearch(query, open);

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
  const searchable = normalizeQuery(q);
  // Results for an earlier query stay up while the next one loads.
  const data = searchable ? search.data : null;

  // The highlighted item. cmdk picks the first item as you type, which is
  // "Show all" while results are loading; when results arrive, move to the
  // first one (adjusting state during render, not in an effect).
  const [selected, setSelected] = React.useState("");
  const [seenData, setSeenData] = React.useState(data);
  if (data !== seenData) {
    setSeenData(data);
    const first = firstResultValue(data);
    if (first) setSelected(first);
  }

  const pageGroups = [
    ...visibleNavConfig(hasSwarm).map((g) => ({ heading: g.title ?? "Pages", items: g.items })),
    { heading: "Settings", items: settingsSections },
  ]
    .map((g) => ({ ...g, items: g.items.filter((i) => matches(i, q)) }))
    .filter((g) => g.items.length > 0);
  const actions = (isAdmin ? ACTIONS : []).filter((a) => matches(a, q));
  const themes = [
    { title: "Light", keywords: ["theme"], icon: Sun, value: "light" },
    { title: "Dark", keywords: ["theme"], icon: Moon, value: "dark" },
    { title: "System", keywords: ["theme"], icon: Laptop, value: "system" },
  ].filter((t) => matches(t, q));
  const shortcuts = [
    {
      title: "Toggle sidebar",
      keywords: ["shortcut"],
      icon: PanelLeft,
      key: "B",
      run: toggleSidebar,
    },
    {
      title: "Open this menu",
      keywords: ["shortcut", "search", "command"],
      icon: Keyboard,
      key: "K",
      run: () => undefined,
    },
  ].filter((s) => matches(s, q));
  const nothingElse = pageGroups.length + actions.length + themes.length + shortcuts.length === 0;

  return (
    <CommandDialog
      modal
      open={open}
      onOpenChange={onOpenChange}
      commandProps={{ shouldFilter: false, value: selected, onValueChange: setSelected }}
    >
      <CommandInput
        placeholder="Search CVEs, packages, images, hosts, agents or pages…"
        value={query}
        onValueChange={setQuery}
      />
      <CommandList>
        <ScrollArea type="hover" className="h-80 pr-1">
          <SearchStatus
            query={q}
            loading={search.loading}
            error={search.error}
            empty={!!searchable && !!data && !hasResults(data) && nothingElse}
          />
          {data && <SearchResultGroups data={data} onSelect={go} />}
          {searchable && <ShowAllGroup query={searchable} onSelect={go} />}
          {pageGroups.map((group) => (
            <CommandGroup key={group.heading} heading={group.heading}>
              {group.items.map((item) => (
                <CommandItem
                  key={item.url}
                  value={`page:${item.url}`}
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
          {actions.length > 0 && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Actions">
                {actions.map((a) => (
                  <CommandItem key={a.title} value={`action:${a.title}`} onSelect={() => go(a.url)}>
                    <a.icon />
                    <span>{a.title}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}
          {themes.length > 0 && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Theme">
                {themes.map((t) => (
                  <CommandItem
                    key={t.value}
                    value={`theme:${t.value}`}
                    onSelect={() => run(() => setTheme(t.value))}
                  >
                    <t.icon />
                    <span>{t.title}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}
          {shortcuts.length > 0 && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Keyboard shortcuts">
                {shortcuts.map((s) => (
                  <CommandItem key={s.key} value={`shortcut:${s.key}`} onSelect={() => run(s.run)}>
                    <s.icon />
                    <span>{s.title}</span>
                    <Shortcut keyName={s.key} className="ml-auto" />
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}
        </ScrollArea>
      </CommandList>
    </CommandDialog>
  );
}
