"use client";
"use no memo";

import type { ReactTable } from "@tanstack/react-table";
import type { ReactNode } from "react";
import { ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

import type { DataTableFeatures } from "./features";

const PAGE_SIZES = [10, 20, 50, 100];

// Row count, page size and page navigation. getRowCount() is the filtered
// total in client mode and the server's `rowCount` in server mode.
export function DataTablePagination<TData extends object>({
  table,
}: {
  table: ReactTable<DataTableFeatures, TData>;
}) {
  const { pageIndex, pageSize } = table.state.pagination;
  const total = table.getRowCount();
  const pageCount = Math.max(table.getPageCount(), 1);
  if (total <= PAGE_SIZES[0] && pageIndex === 0) {
    return (
      <p className="text-muted-foreground px-1 text-sm">
        {total} {total === 1 ? "row" : "rows"}
      </p>
    );
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 px-1">
      <p className="text-muted-foreground text-sm">
        {total} {total === 1 ? "row" : "rows"}
      </p>
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2 text-sm">
          <span className="text-muted-foreground hidden sm:inline">Rows per page</span>
          <Select value={String(pageSize)} onValueChange={(v) => table.setPageSize(Number(v))}>
            <SelectTrigger className="h-8 w-18" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent side="top">
              {PAGE_SIZES.map((n) => (
                <SelectItem key={n} value={String(n)}>
                  {n}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <span className="text-sm tabular-nums">
          Page {pageIndex + 1} of {pageCount}
        </span>
        <div className="flex items-center gap-1">
          <PageButton
            label="First page"
            onClick={() => table.firstPage()}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronsLeft className="size-4" />
          </PageButton>
          <PageButton
            label="Previous page"
            onClick={() => table.previousPage()}
            disabled={!table.getCanPreviousPage()}
          >
            <ChevronLeft className="size-4" />
          </PageButton>
          <PageButton
            label="Next page"
            onClick={() => table.nextPage()}
            disabled={!table.getCanNextPage()}
          >
            <ChevronRight className="size-4" />
          </PageButton>
          <PageButton
            label="Last page"
            onClick={() => table.lastPage()}
            disabled={!table.getCanLastPage()}
          >
            <ChevronsRight className="size-4" />
          </PageButton>
        </div>
      </div>
    </div>
  );
}

function PageButton(props: {
  label: string;
  onClick: () => void;
  disabled: boolean;
  children: ReactNode;
}) {
  return (
    <Button
      variant="outline"
      size="icon"
      className="size-8"
      aria-label={props.label}
      onClick={props.onClick}
      disabled={props.disabled}
    >
      {props.children}
    </Button>
  );
}
