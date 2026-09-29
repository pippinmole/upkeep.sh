"use client";
"use no memo";

import type { Column } from "@tanstack/react-table";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

import type { DataTableFeatures } from "./features";

// Header cell that toggles sorting on click (asc → desc → none). Falls back
// to plain text for columns that can't sort. The button's name is just the
// title; DataTable puts the sort state on the <th> as aria-sort.
export function DataTableColumnHeader<TData extends object, TValue>({
  column,
  title,
  className,
}: {
  column: Column<DataTableFeatures, TData, TValue>;
  title: string;
  className?: string;
}) {
  if (!column.getCanSort()) return <div className={className}>{title}</div>;

  const sorted = column.getIsSorted();
  const Icon = sorted === "asc" ? ArrowUp : sorted === "desc" ? ArrowDown : ChevronsUpDown;
  return (
    <Button
      variant="ghost"
      size="sm"
      className={cn("-ml-3 h-8", className)}
      onClick={column.getToggleSortingHandler()}
    >
      {title}
      <Icon className={cn("size-3.5", !sorted && "text-muted-foreground/60")} aria-hidden />
    </Button>
  );
}
