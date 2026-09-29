import {
  columnFacetingFeature,
  columnFilteringFeature,
  columnVisibilityFeature,
  createColumnHelper,
  createExpandedRowModel,
  createFacetedRowModel,
  createFacetedUniqueValues,
  createFilteredRowModel,
  createPaginatedRowModel,
  createSortedRowModel,
  filterFn_arrHas,
  filterFn_includesString,
  globalFilteringFeature,
  rowExpandingFeature,
  rowPaginationFeature,
  rowSortingFeature,
  sortFn_alphanumeric,
  sortFn_basic,
  sortFn_datetime,
  sortFn_text,
  tableFeatures,
  type ColumnDef,
  type RowData,
} from "@tanstack/react-table";

// Per-column options DataTable reads from `columnDef.meta`.
export type DataTableColumnMeta = {
  // Classes for both the header and the body cells of the column, e.g.
  // "text-right tabular-nums" for a numeric column.
  className?: string;
};

// The one TanStack Table v9 feature set every DataTable uses (v9 registers
// features and row models explicitly). In server mode the row models are
// bypassed by manualSorting / manualFiltering / manualPagination.
export const dataTableFeatures = tableFeatures({
  columnFilteringFeature,
  globalFilteringFeature,
  rowSortingFeature,
  rowPaginationFeature,
  rowExpandingFeature,
  columnVisibilityFeature,
  columnFacetingFeature,
  filteredRowModel: createFilteredRowModel(),
  sortedRowModel: createSortedRowModel(),
  paginatedRowModel: createPaginatedRowModel(),
  expandedRowModel: createExpandedRowModel(),
  facetedRowModel: createFacetedRowModel(),
  facetedUniqueValues: createFacetedUniqueValues(),
  // "arrHas": scalar value equals one of the selected values (faceted filter).
  filterFns: { includesString: filterFn_includesString, arrHas: filterFn_arrHas },
  sortFns: {
    alphanumeric: sortFn_alphanumeric,
    basic: sortFn_basic,
    datetime: sortFn_datetime,
    text: sortFn_text,
  },
  // Type-only slot: types `columnDef.meta` (the value is never read).
  columnMeta: {} as DataTableColumnMeta,
});

export type DataTableFeatures = typeof dataTableFeatures;

// oxlint-disable-next-line typescript/no-explicit-any -- column value types vary per column
export type DataTableColumnDef<TData extends RowData> = ColumnDef<DataTableFeatures, TData, any>;

export function dataTableColumnHelper<TData extends RowData>() {
  return createColumnHelper<DataTableFeatures, TData>();
}
