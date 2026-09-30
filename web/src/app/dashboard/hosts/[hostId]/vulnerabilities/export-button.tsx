import { Download } from "lucide-react";

import { Button } from "@/components/ui/button";

// Downloads export/route.ts as CSV for the current status tab and filters,
// across every page. The label says whether that's everything or a
// filtered subset, and how many rows it holds.
export function ExportButton({
  href,
  total,
  status,
  filtered,
}: {
  href: string;
  total: number;
  status: "open" | "resolved";
  filtered: boolean;
}) {
  const noun = total === 1 ? "vulnerability" : "vulnerabilities";
  const title = filtered
    ? `Download the ${total} ${status} ${noun} matching the current filters as CSV (all pages)`
    : `Download all ${total} ${status} ${noun} as CSV`;
  return (
    <Button asChild variant="outline">
      {/* A plain <a>: a route handler download, not a client navigation. */}
      <a href={href} download title={title} aria-label={title}>
        <Download aria-hidden />
        {filtered ? `Export filtered (${total})` : `Export all (${total})`}
      </a>
    </Button>
  );
}
