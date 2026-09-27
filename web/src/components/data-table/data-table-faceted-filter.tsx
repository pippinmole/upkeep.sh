"use client";
"use no memo";

import type { Column } from "@tanstack/react-table";
import { PlusCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import type { DataTableFeatures } from "./features";

// Multi-select filter over one column. The column should use
// `filterFn: "arrHas"` (value equals one of the selected options).
export function DataTableFacetedFilter<TData extends object>({
  column,
  title,
  options,
  showCounts,
}: {
  column: Column<DataTableFeatures, TData, unknown>;
  title: string;
  options: { value: string; label: string }[];
  showCounts: boolean;
}) {
  const counts = showCounts ? column.getFacetedUniqueValues() : null;
  const raw = column.getFilterValue();
  const selected = new Set(Array.isArray(raw) ? (raw as string[]) : []);

  const toggle = (value: string, on: boolean) => {
    const next = new Set(selected);
    if (on) next.add(value);
    else next.delete(value);
    column.setFilterValue(next.size ? [...next] : undefined);
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className="h-9 border-dashed">
          <PlusCircle className="size-4" />
          {title}
          {selected.size > 0 && (
            <Badge variant="secondary" className="ml-1 rounded-sm px-1 font-normal">
              {selected.size > 2
                ? `${selected.size} selected`
                : options
                    .filter((o) => selected.has(o.value))
                    .map((o) => o.label)
                    .join(", ")}
            </Badge>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-52">
        <DropdownMenuLabel>{title}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {options.map((o) => (
          <DropdownMenuCheckboxItem
            key={o.value}
            checked={selected.has(o.value)}
            onCheckedChange={(on) => toggle(o.value, on === true)}
            onSelect={(e) => e.preventDefault()}
          >
            <span className="flex-1">{o.label}</span>
            {counts && (
              <span className="text-muted-foreground ml-auto font-mono text-xs">
                {counts.get(o.value) ?? 0}
              </span>
            )}
          </DropdownMenuCheckboxItem>
        ))}
        {selected.size > 0 && (
          <>
            <DropdownMenuSeparator />
            <DropdownMenuItem onSelect={() => column.setFilterValue(undefined)}>
              Clear filter
            </DropdownMenuItem>
          </>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
