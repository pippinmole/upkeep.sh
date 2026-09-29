import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";
import { type SearchParams, withParams } from "@/lib/search-params";

interface Props {
  basePath: string;
  searchParams: SearchParams;
  page: number;
  pageSize: number;
  total: number;
}

const DISABLED = {
  "aria-disabled": true,
  tabIndex: -1,
  className: "pointer-events-none opacity-50",
};

// Offset pagination driven by ?page=. Server-rendered links only. Worded
// like DataTablePagination ("Page 2 of 5"). Renders nothing for an empty
// result: the table shows its own no-results message.
export function Pager({ basePath, searchParams, page, pageSize, total }: Props) {
  if (total === 0) return null;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const first = (page - 1) * pageSize + 1;
  const last = Math.min(total, page * pageSize);
  const href = (p: number) =>
    `${basePath}${withParams(searchParams, { page: p === 1 ? null : p })}`;
  const n = (x: number) => x.toLocaleString("en-US");

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 px-1">
      <p className="text-muted-foreground text-sm tabular-nums">
        {first > total
          ? `${n(total)} ${total === 1 ? "row" : "rows"}`
          : `Showing ${n(first)}–${n(last)} of ${n(total)}`}
      </p>
      {pages > 1 && (
        <div className="flex items-center gap-4">
          <span className="text-sm tabular-nums">
            Page {n(page)} of {n(pages)}
          </span>
          <Pagination className="mx-0 w-auto">
            <PaginationContent>
              <PaginationItem>
                {page > 1 ? (
                  <PaginationPrevious href={href(Math.min(page - 1, pages))} />
                ) : (
                  <PaginationPrevious href={href(1)} {...DISABLED} />
                )}
              </PaginationItem>
              <PaginationItem>
                {page < pages ? (
                  <PaginationNext href={href(page + 1)} />
                ) : (
                  <PaginationNext href={href(pages)} {...DISABLED} />
                )}
              </PaginationItem>
            </PaginationContent>
          </Pagination>
        </div>
      )}
    </div>
  );
}
