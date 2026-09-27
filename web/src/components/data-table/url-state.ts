"use client";

import { usePathname, useRouter, useSearchParams } from "next/navigation";

import type { DataTableServer, DataTableServerState } from "./data-table";
import { toParams, type TableUrlOptions } from "./url-params";

// Wires DataTable's `server` prop to the URL: pass the state parsed on the
// server plus the total row count; changes navigate (router.replace), which
// re-renders the Server Component with the new page of rows.
export function useServerTable(
  state: DataTableServerState,
  rowCount: number,
  opts: TableUrlOptions,
): DataTableServer {
  const router = useRouter();
  const pathname = usePathname();
  const search = useSearchParams();
  return {
    rowCount,
    state,
    onStateChange: (next) => {
      const qs = toParams(next, opts, new URLSearchParams(search.toString())).toString();
      router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
    },
  };
}
