"use client";

import { Search, X } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { MachineFilters } from "@/lib/machines";
import { withParams } from "@/lib/search-params";
import { cn } from "@/lib/utils";

// Writes filter changes into the URL (search-params.ts conventions), so a
// filtered list can be shared and survives a reload. replace, not push: a
// filter tweak isn't a history entry.
export function useSetFilterParams() {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  return useCallback(
    (overrides: Record<string, string | null>) => {
      const href = pathname + withParams(Object.fromEntries(searchParams), overrides);
      router.replace(href, { scroll: false });
    },
    [router, pathname, searchParams],
  );
}

// Every filter key except `archived`, which is view state (the toggle
// under the list), not a filter: "Clear" leaves it alone.
export const CLEAR_FILTERS = { q: null, status: null, os: null, critical: null, kev: null };

export function hasActiveFilters(f: MachineFilters): boolean {
  return f.q !== null || f.status !== null || f.os !== null || f.critical || f.kev;
}

const STATUS_OPTIONS = [
  { value: "online", label: "Online" },
  { value: "stale", label: "Stale" },
  { value: "never", label: "Never reported" },
];

export function MachineToolbar({
  filters,
  osOptions,
  searchKey,
  onClear,
}: {
  filters: MachineFilters;
  osOptions: { value: string; label: string }[];
  // Bumped by the list on "Clear" to reset the search box.
  searchKey: number;
  onClear: () => void;
}) {
  const set = useSetFilterParams();

  return (
    <div className="flex flex-wrap items-center gap-2">
      <SearchBox key={searchKey} initial={filters.q ?? ""} onSearch={(q) => set({ q })} />
      <Select
        value={filters.status ?? "all"}
        onValueChange={(v) => set({ status: v === "all" ? null : v })}
      >
        <SelectTrigger className="w-40" aria-label="Status">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All statuses</SelectItem>
          {STATUS_OPTIONS.map((o) => (
            <SelectItem key={o.value} value={o.value}>
              {o.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {osOptions.length > 0 && (
        <Select
          value={filters.os ?? "all"}
          onValueChange={(v) => set({ os: v === "all" ? null : v })}
        >
          <SelectTrigger className="w-44" aria-label="Operating system">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All operating systems</SelectItem>
            {osOptions.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      )}
      <ToggleChip pressed={filters.critical} onToggle={(on) => set({ critical: on ? "1" : null })}>
        Critical, packages or images
      </ToggleChip>
      <ToggleChip pressed={filters.kev} onToggle={(on) => set({ kev: on ? "1" : null })}>
        Known exploited
      </ToggleChip>
      {hasActiveFilters(filters) && (
        <Button variant="ghost" size="sm" className="text-muted-foreground" onClick={onClear}>
          <X aria-hidden />
          Clear
        </Button>
      )}
    </div>
  );
}

// Local text state so typing stays instant; the URL follows 200ms after
// the last keystroke.
function SearchBox({
  initial,
  onSearch,
}: {
  initial: string;
  onSearch: (q: string | null) => void;
}) {
  const [value, setValue] = useState(initial);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  return (
    <div className="relative w-full sm:w-64">
      <Search className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
      <Input
        type="search"
        value={value}
        placeholder="Search name, OS or IP"
        aria-label="Search machines"
        className="pl-8"
        onChange={(e) => {
          const next = e.target.value;
          setValue(next);
          clearTimeout(timer.current);
          timer.current = setTimeout(() => onSearch(next.trim() || null), 200);
        }}
      />
    </div>
  );
}

function ToggleChip({
  pressed,
  onToggle,
  children,
}: {
  pressed: boolean;
  onToggle: (pressed: boolean) => void;
  children: React.ReactNode;
}) {
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      aria-pressed={pressed}
      onClick={() => onToggle(!pressed)}
      className={cn(
        "rounded-full",
        pressed &&
          "bg-primary text-primary-foreground hover:bg-primary/90 hover:text-primary-foreground border-transparent",
      )}
    >
      {children}
    </Button>
  );
}
