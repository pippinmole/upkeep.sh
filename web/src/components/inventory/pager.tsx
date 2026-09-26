import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
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

// Offset pagination driven by ?page=. Server-rendered links only.
export function Pager({ basePath, searchParams, page, pageSize, total }: Props) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const first = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const last = Math.min(total, page * pageSize);
  const href = (p: number) =>
    `${basePath}${withParams(searchParams, { page: p === 1 ? null : p })}`;

  return (
    <div className="flex flex-wrap items-center justify-between gap-2 py-3">
      <p className="text-muted-foreground text-sm">
        {total === 0 ? "No results" : `${first}–${last} of ${total}`}
      </p>
      {pages > 1 && (
        <Pagination className="mx-0 w-auto">
          <PaginationContent>
            <PaginationItem>
              {page > 1 ? (
                <PaginationPrevious href={href(page - 1)} />
              ) : (
                <PaginationPrevious
                  href={href(1)}
                  aria-disabled
                  tabIndex={-1}
                  className="pointer-events-none opacity-50"
                />
              )}
            </PaginationItem>
            <PaginationItem>
              <PaginationLink href={href(page)} isActive size="default">
                {page} / {pages}
              </PaginationLink>
            </PaginationItem>
            <PaginationItem>
              {page < pages ? (
                <PaginationNext href={href(page + 1)} />
              ) : (
                <PaginationNext
                  href={href(pages)}
                  aria-disabled
                  tabIndex={-1}
                  className="pointer-events-none opacity-50"
                />
              )}
            </PaginationItem>
          </PaginationContent>
        </Pagination>
      )}
    </div>
  );
}
