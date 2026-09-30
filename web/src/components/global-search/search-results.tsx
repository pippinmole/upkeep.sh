"use client";

import {
  Boxes,
  Container,
  type LucideIcon,
  Package,
  RadioTower,
  Server,
  ShieldAlert,
} from "lucide-react";

import { CommandGroup, CommandItem } from "@/components/ui/command";
import type { SearchResponse, SearchResult } from "@/lib/search/map";
import type { SearchGroup } from "@/lib/search/sql";
import { cn } from "@/lib/utils";

// Display order and headings of the server's result groups.
const GROUPS: { key: SearchGroup; heading: string; icon: LucideIcon }[] = [
  { key: "vulnerabilities", heading: "Vulnerabilities", icon: ShieldAlert },
  { key: "hosts", heading: "Hosts", icon: Server },
  { key: "packages", heading: "Packages", icon: Package },
  { key: "images", heading: "Images", icon: Boxes },
  { key: "containers", heading: "Containers", icon: Container },
  { key: "agents", heading: "Agents", icon: RadioTower },
];

export function hasResults(data: SearchResponse | null): boolean {
  return !!data && GROUPS.some((g) => data.groups[g.key].length > 0);
}

// The cmdk value of the first result, to select it when results arrive
// (otherwise the selection stays on whatever was first while loading).
export function firstResultValue(data: SearchResponse | null): string | null {
  if (!data) return null;
  for (const { key } of GROUPS) {
    const r = data.groups[key][0];
    if (r) return itemValue(key, r);
  }
  return null;
}

const itemValue = (group: SearchGroup, r: SearchResult) => `${group}:${r.id}`;

function ResultItem({
  group,
  result,
  icon: Icon,
  onSelect,
}: {
  group: SearchGroup;
  result: SearchResult;
  icon: LucideIcon;
  onSelect: (href: string) => void;
}) {
  return (
    <CommandItem value={itemValue(group, result)} onSelect={() => onSelect(result.href)}>
      <Icon className="text-muted-foreground" />
      <div className="flex min-w-0 flex-1 flex-col">
        <span className={cn("truncate", group === "vulnerabilities" && "font-mono")}>
          {result.title}
        </span>
        {result.subtitle && (
          <span className="text-muted-foreground truncate text-xs">{result.subtitle}</span>
        )}
      </div>
      {result.badge && (
        <span
          className={cn(
            "ml-auto shrink-0 rounded border px-1.5 py-0.5 text-[10px] font-medium uppercase",
            result.badge === "KEV"
              ? "border-destructive/40 text-destructive"
              : "text-muted-foreground",
          )}
        >
          {result.badge}
        </span>
      )}
    </CommandItem>
  );
}

// One cmdk group per non-empty result type, in GROUPS order.
export function SearchResultGroups({
  data,
  onSelect,
}: {
  data: SearchResponse;
  onSelect: (href: string) => void;
}) {
  return (
    <>
      {GROUPS.map(({ key, heading, icon }) =>
        data.groups[key].length === 0 ? null : (
          <CommandGroup key={key} heading={heading}>
            {data.groups[key].map((r) => (
              <ResultItem key={r.id} group={key} result={r} icon={icon} onSelect={onSelect} />
            ))}
          </CommandGroup>
        ),
      )}
    </>
  );
}
