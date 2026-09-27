import type { SearchParams } from "@/lib/search-params";
import { pageParam, param } from "@/lib/search-params";

import type { DataTableServerState } from "./data-table";

// Server-mode DataTable state <-> URL search params (DOMAIN_MODEL.md §3,
// Q11). Same keys the FilterBar tables use: ?q= search, ?page= (1-based),
// ?sort=col or ?sort=-col (desc), ?size=, and one ?<columnId>=a,b per
// faceted filter. The Server Component parses with tableStateFromParams and
// queries with the result (every value is still untrusted: bind it, and
// check sort / filter values against allowlists before building SQL).

export type TableUrlOptions = {
  sortKeys: readonly string[]; // allowed ?sort columns
  filterKeys?: readonly string[]; // columns with a faceted filter
  defaultSort?: { id: string; desc: boolean };
  defaultPageSize?: number;
};

const SIZES = [10, 20, 50, 100];

export function tableStateFromParams(
  sp: SearchParams,
  opts: TableUrlOptions,
): DataTableServerState {
  const sortRaw = param(sp, "sort");
  const desc = sortRaw?.startsWith("-") ?? false;
  const sortId = sortRaw?.replace(/^-/, "");
  const sorting =
    sortId && opts.sortKeys.includes(sortId)
      ? [{ id: sortId, desc }]
      : opts.defaultSort
        ? [opts.defaultSort]
        : [];
  const size = Number(param(sp, "size"));
  return {
    sorting,
    pagination: {
      pageIndex: pageParam(sp) - 1,
      pageSize: SIZES.includes(size) ? size : (opts.defaultPageSize ?? 20),
    },
    globalFilter: param(sp, "q") ?? "",
    columnFilters: (opts.filterKeys ?? []).flatMap((id) => {
      const v = param(sp, id);
      return v ? [{ id, value: v.split(",").slice(0, 20) }] : [];
    }),
  };
}

export function toParams(s: DataTableServerState, opts: TableUrlOptions, base: URLSearchParams) {
  const out = new URLSearchParams(base);
  for (const k of ["q", "page", "sort", "size", ...(opts.filterKeys ?? [])]) out.delete(k);
  if (s.globalFilter) out.set("q", s.globalFilter);
  if (s.pagination.pageIndex > 0) out.set("page", String(s.pagination.pageIndex + 1));
  if (s.pagination.pageSize !== (opts.defaultPageSize ?? 20))
    out.set("size", String(s.pagination.pageSize));
  const sort = s.sorting[0];
  const d = opts.defaultSort;
  if (sort && !(d && d.id === sort.id && d.desc === sort.desc))
    out.set("sort", sort.desc ? `-${sort.id}` : sort.id);
  for (const f of s.columnFilters) {
    if (Array.isArray(f.value) && f.value.length) out.set(f.id, f.value.join(","));
  }
  return out;
}
