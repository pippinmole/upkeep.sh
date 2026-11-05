"use client";

import { X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { TooltipProvider } from "@/components/ui/tooltip";
import { filterMachines, type MachineRow as Machine, parseMachineFilters } from "@/lib/machines";
import { osName } from "@/lib/os";

import { MachineRow } from "./machine-row";
import {
  CLEAR_FILTERS,
  hasActiveFilters,
  MachineToolbar,
  useSetFilterParams,
} from "./machine-toolbar";

// The machine list: toolbar, then one row per machine in the order the
// query returned (alphabetical by hostname; never re-sorted here). Filters
// come from the URL (read client-side, so changing them makes no server
// request) and run here over the fetched rows.
export function MachineList({ rows }: { rows: Machine[] }) {
  const set = useSetFilterParams();
  const searchParams = useSearchParams();
  const filters = useMemo(
    () => parseMachineFilters(Object.fromEntries(searchParams)),
    [searchParams],
  );
  const [searchKey, setSearchKey] = useState(0);
  const visible = filterMachines(rows, filters);
  const archivedCount = rows.filter((m) => m.archivedAt !== null).length;
  const filtered = hasActiveFilters(filters);

  const clear = () => {
    set(CLEAR_FILTERS);
    setSearchKey((k) => k + 1);
  };

  return (
    <TooltipProvider delayDuration={200}>
      <div className="flex flex-col gap-4">
        <MachineToolbar
          filters={filters}
          osOptions={osOptions(rows, filters.os)}
          searchKey={searchKey}
          set={set}
          onClear={clear}
        />

        {visible.length === 0 ? (
          <div className="text-muted-foreground flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-12 text-center text-sm">
            {filtered ? (
              <>
                <p className="text-foreground font-medium">No machines match</p>
                <Button variant="outline" size="sm" onClick={clear}>
                  <X aria-hidden />
                  Clear filters
                </Button>
              </>
            ) : (
              <p>Every machine is archived.</p>
            )}
          </div>
        ) : (
          <div className="md:bg-card md:overflow-x-auto md:rounded-lg md:border">
            <table className="w-full text-sm max-md:block">
              <thead className="max-md:hidden">
                <tr className="text-muted-foreground border-b text-left text-xs">
                  <th scope="col" className="px-3 py-2 font-medium">
                    Machine
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    OS
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Last seen
                  </th>
                  <th scope="col" className="px-3 py-2 font-medium">
                    Open vulnerabilities
                  </th>
                  <th scope="col" className="w-0 px-3 py-2">
                    <span className="sr-only">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody className="max-md:flex max-md:flex-col max-md:gap-2">
                {visible.map((m) => (
                  <MachineRow key={m.id} machine={m} />
                ))}
              </tbody>
            </table>
          </div>
        )}

        {archivedCount > 0 && (
          <div>
            <Button
              variant="ghost"
              size="sm"
              className="text-muted-foreground tabular-nums"
              onClick={() => set({ archived: filters.archived ? null : "1" })}
            >
              {filters.archived ? "Hide archived" : `Show ${archivedCount} archived`}
            </Button>
          </div>
        )}
      </div>
    </TooltipProvider>
  );
}

// The OS filter offers the systems present in the workspace, plus the
// current value if it matches none (a stale shared link), so the select
// can still show it.
function osOptions(rows: Machine[], current: string | null): { value: string; label: string }[] {
  const ids = new Set(rows.flatMap((m) => (m.osId ? [m.osId] : [])));
  if (current) ids.add(current);
  return [...ids]
    .map((id) => ({ value: id, label: osName(id) }))
    .sort((a, b) => a.label.localeCompare(b.label));
}
