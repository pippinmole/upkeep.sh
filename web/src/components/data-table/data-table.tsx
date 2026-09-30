"use client";
"use no memo"; // table methods read live state; compiler memoization would go stale

import {
  functionalUpdate,
  useTable,
  type Column,
  type ColumnFiltersState,
  type ColumnVisibilityState,
  type FilterFn,
  type PaginationState,
  type Row,
  type SortingState,
  type Updater,
} from "@tanstack/react-table";
import { Fragment, type ReactNode, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import { DataTablePagination } from "./data-table-pagination";
import { DataTableToolbar, type DataTableFacet } from "./data-table-toolbar";
import { dataTableFeatures, type DataTableColumnDef, type DataTableFeatures } from "./features";

// Table state owned by the server (URL) in server mode.
export type DataTableServerState = {
  sorting: SortingState;
  pagination: PaginationState;
  globalFilter: string;
  columnFilters: ColumnFiltersState;
};

export type DataTableServer = {
  rowCount: number; // total rows matching the filters, across all pages
  state: DataTableServerState;
  onStateChange: (next: DataTableServerState) => void;
};

export interface DataTableProps<TData extends object> {
  columns: DataTableColumnDef<TData>[];
  data: TData[];
  getRowId?: (row: TData) => string;
  // Homogeneous children (same columns), expanded in place.
  getSubRows?: (row: TData) => TData[] | undefined;
  // Heterogeneous children: rendered in a full-width row under an expanded row.
  renderSubRows?: (row: Row<DataTableFeatures, TData>) => ReactNode;
  getRowCanExpand?: (row: Row<DataTableFeatures, TData>) => boolean;
  // Extra classes for a row, e.g. dimming a disabled item.
  getRowClassName?: (row: TData) => string | undefined;
  globalFilterFn?: FilterFn<DataTableFeatures, TData>;
  searchPlaceholder?: string;
  facets?: DataTableFacet[];
  initialSorting?: SortingState;
  // Client mode only: column filters applied on first render (e.g. a
  // facet that hides archived rows by default).
  initialColumnFilters?: ColumnFiltersState;
  initialVisibility?: ColumnVisibilityState;
  pageSize?: number;
  // Shown when there are no rows and no filter is active; with a filter
  // active the table says so and offers to clear it.
  emptyMessage?: ReactNode;
  // Server-driven mode: sorting / filtering / pagination happen in SQL and
  // `data` is one page. See url-state.ts for syncing `state` with the URL.
  server?: DataTableServer;
}

const EMPTY_FILTERS: ColumnFiltersState = [];

// aria-sort for a sortable column's header; none for columns that can't sort.
function ariaSort<TData extends object>(
  column: Column<DataTableFeatures, TData>,
): "ascending" | "descending" | "none" | undefined {
  if (!column.getCanSort()) return undefined;
  const sorted = column.getIsSorted();
  return sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none";
}

export function DataTable<TData extends object>(props: DataTableProps<TData>) {
  const { columns, data, server, renderSubRows } = props;
  const [sorting, setSorting] = useState<SortingState>(props.initialSorting ?? []);
  const [globalFilter, setGlobalFilter] = useState("");
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>(
    props.initialColumnFilters ?? EMPTY_FILTERS,
  );
  const [pagination, setPagination] = useState<PaginationState>({
    pageIndex: 0,
    pageSize: props.pageSize ?? 20,
  });
  const [columnVisibility, setColumnVisibility] = useState<ColumnVisibilityState>(
    props.initialVisibility ?? {},
  );

  // Server mode: any change except paging itself goes back to page 1.
  const push = <K extends keyof DataTableServerState>(
    key: K,
    updater: Updater<DataTableServerState[K]>,
  ) => {
    if (!server) return;
    const next = { ...server.state, [key]: functionalUpdate(updater, server.state[key]) };
    if (key !== "pagination") next.pagination = { ...next.pagination, pageIndex: 0 };
    server.onStateChange(next);
  };

  const table = useTable({
    features: dataTableFeatures,
    columns,
    data,
    getRowId: props.getRowId ? (row) => props.getRowId!(row) : undefined,
    getSubRows: props.getSubRows,
    getRowCanExpand: props.getRowCanExpand,
    globalFilterFn: props.globalFilterFn ?? "includesString",
    manualSorting: !!server,
    manualFiltering: !!server,
    manualPagination: !!server,
    rowCount: server?.rowCount,
    state: {
      sorting: server?.state.sorting ?? sorting,
      globalFilter: server?.state.globalFilter ?? globalFilter,
      columnFilters: server?.state.columnFilters ?? columnFilters,
      pagination: server?.state.pagination ?? pagination,
      columnVisibility,
    },
    onSortingChange: server ? (u) => push("sorting", u) : setSorting,
    onGlobalFilterChange: server ? (u) => push("globalFilter", u) : setGlobalFilter,
    onColumnFiltersChange: server ? (u) => push("columnFilters", u) : setColumnFilters,
    onPaginationChange: server ? (u) => push("pagination", u) : setPagination,
    onColumnVisibilityChange: setColumnVisibility,
  });

  const rows = table.getRowModel().rows;
  const colSpan = table.getVisibleLeafColumns().length;
  const filtered =
    String(table.state.globalFilter ?? "") !== "" || table.state.columnFilters.length > 0;
  // The toolbar re-syncs its search box from the cleared global filter.
  const clearFilters = () => {
    table.setGlobalFilter("");
    table.resetColumnFilters(true);
  };

  return (
    <div className="flex flex-col gap-3">
      <DataTableToolbar
        table={table}
        searchPlaceholder={props.searchPlaceholder}
        facets={props.facets}
        serverMode={!!server}
      />
      <div className="border-border bg-card overflow-hidden rounded-lg border">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id}>
                {group.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    colSpan={header.colSpan}
                    className={header.column.columnDef.meta?.className}
                    aria-sort={header.isPlaceholder ? undefined : ariaSort(header.column)}
                  >
                    {header.isPlaceholder ? null : <table.FlexRender header={header} />}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow>
                <TableCell colSpan={colSpan} className="text-muted-foreground h-24 text-center">
                  {filtered ? (
                    <div className="flex flex-col items-center gap-2">
                      <span>No results match these filters.</span>
                      <Button variant="outline" size="sm" onClick={clearFilters}>
                        Clear filters
                      </Button>
                    </div>
                  ) : (
                    (props.emptyMessage ?? "No results.")
                  )}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <Fragment key={row.id}>
                  <TableRow
                    data-state={row.getIsExpanded() ? "expanded" : undefined}
                    className={props.getRowClassName?.(row.original)}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <TableCell key={cell.id} className={cell.column.columnDef.meta?.className}>
                        <table.FlexRender cell={cell} />
                      </TableCell>
                    ))}
                  </TableRow>
                  {renderSubRows && row.getIsExpanded() && (
                    <TableRow className="bg-muted/30 hover:bg-muted/30">
                      <TableCell colSpan={colSpan} className="p-0">
                        {renderSubRows(row)}
                      </TableCell>
                    </TableRow>
                  )}
                </Fragment>
              ))
            )}
          </TableBody>
        </Table>
      </div>
      <DataTablePagination table={table} />
    </div>
  );
}
