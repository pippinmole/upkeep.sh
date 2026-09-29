"use client";
"use no memo";

import type { ReactTable } from "@tanstack/react-table";
import { Settings2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import type { DataTableFeatures } from "./features";

// Column visibility toggle. Labels come from the column's `header` when it's
// a string, else the column id.
export function DataTableViewOptions<TData extends object>({
  table,
}: {
  table: ReactTable<DataTableFeatures, TData>;
}) {
  const columns = table.getAllLeafColumns().filter((c) => c.getCanHide());
  if (columns.length === 0) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        {/* Icon-only below lg; the aria-label matches the visible text. */}
        <Button variant="outline" size="sm" className="ml-auto h-9" aria-label="Columns">
          <Settings2 className="size-4" />
          <span className="hidden lg:inline">Columns</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-44">
        <DropdownMenuLabel>Toggle columns</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {columns.map((column) => {
          const header = column.columnDef.header;
          return (
            <DropdownMenuCheckboxItem
              key={column.id}
              checked={column.getIsVisible()}
              onCheckedChange={(on) => column.toggleVisibility(on === true)}
              onSelect={(e) => e.preventDefault()}
            >
              {typeof header === "string" ? header : column.id}
            </DropdownMenuCheckboxItem>
          );
        })}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
