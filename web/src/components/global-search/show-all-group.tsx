"use client";

import { Search as SearchIcon } from "lucide-react";

import { CommandGroup, CommandItem } from "@/components/ui/command";
import { listHref } from "@/lib/search/links";

// The fleet lists that take ?q=, for "everything matching", past the few
// results per group. Vulnerabilities matches CVE ids and source packages.
const LISTS = [
  { list: "vulnerabilities", label: "vulnerabilities" },
  { list: "packages", label: "packages" },
  { list: "images", label: "images" },
] as const;

export function ShowAllGroup({
  query,
  onSelect,
}: {
  query: string;
  onSelect: (href: string) => void;
}) {
  return (
    <CommandGroup heading="Show all">
      {LISTS.map(({ list, label }) => (
        <CommandItem
          key={list}
          value={`all:${list}`}
          onSelect={() => onSelect(listHref(list, query))}
        >
          <SearchIcon className="text-muted-foreground" />
          <span>
            All {label} matching <span className="font-medium">“{query}”</span>
          </span>
        </CommandItem>
      ))}
    </CommandGroup>
  );
}
