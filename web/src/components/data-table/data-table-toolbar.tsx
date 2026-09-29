"use client";
"use no memo";

import type { ReactTable } from "@tanstack/react-table";
import { Search, X } from "lucide-react";
import { useRef, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import { DataTableFacetedFilter } from "./data-table-faceted-filter";
import { DataTableViewOptions } from "./data-table-view-options";
import type { DataTableFeatures } from "./features";

export type DataTableFacet = {
  columnId: string;
  title: string;
  options: { value: string; label: string }[];
};

export function DataTableToolbar<TData extends object>({
  table,
  searchPlaceholder,
  facets,
  serverMode,
}: {
  table: ReactTable<DataTableFeatures, TData>;
  searchPlaceholder?: string;
  facets?: DataTableFacet[];
  serverMode: boolean;
}) {
  const current = String(table.state.globalFilter ?? "");
  const [text, setText] = useState(current);
  // The last value this box pushed, and the last global filter it saw.
  const [pushed, setPushed] = useState(current);
  const [seen, setSeen] = useState(current);
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const filtered = current !== "" || table.state.columnFilters.length > 0;

  // Re-sync the box when the global filter changes from outside it (the
  // empty-state "Clear filters", back/forward in server mode). Its own push
  // echoing back is skipped, so a slow navigation can't clobber typing.
  if (current !== seen) {
    setSeen(current);
    if (current !== pushed) {
      setText(current);
      setPushed(current);
    }
  }

  // Debounced: in server mode each change is a navigation.
  const onSearch = (value: string) => {
    setText(value);
    clearTimeout(timer.current);
    timer.current = setTimeout(
      () => {
        setPushed(value);
        table.setGlobalFilter(value);
      },
      serverMode ? 300 : 100,
    );
  };

  const reset = () => {
    clearTimeout(timer.current);
    setText("");
    setPushed("");
    table.setGlobalFilter("");
    table.resetColumnFilters(true);
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      {searchPlaceholder !== undefined && (
        <div className="relative w-full sm:w-64">
          <Search className="text-muted-foreground pointer-events-none absolute top-1/2 left-2.5 size-4 -translate-y-1/2" />
          <Input
            type="search"
            value={text}
            onChange={(e) => onSearch(e.target.value)}
            placeholder={searchPlaceholder}
            aria-label={searchPlaceholder}
            className="h-9 pl-8"
          />
        </div>
      )}
      {facets?.map((f) => {
        const column = table.getColumn(f.columnId);
        return column ? (
          <DataTableFacetedFilter
            key={f.columnId}
            column={column}
            title={f.title}
            options={f.options}
            showCounts={!serverMode}
          />
        ) : null;
      })}
      {filtered && (
        <Button variant="ghost" size="sm" className="h-9" onClick={reset}>
          Reset
          <X className="size-4" />
        </Button>
      )}
      <DataTableViewOptions table={table} />
    </div>
  );
}
