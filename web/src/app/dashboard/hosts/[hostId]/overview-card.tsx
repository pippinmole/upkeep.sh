import { ArrowRight } from "lucide-react";
import Link from "next/link";
import type { ReactNode } from "react";

import { Card, CardAction, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/utils";

// A host overview card; `href` links its header to the tab with the full
// list.
export function OverviewCard({
  title,
  href,
  linkLabel,
  className,
  children,
}: {
  title: string;
  href?: string;
  linkLabel?: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <Card className={cn("gap-4 py-4", className)}>
      <CardHeader className="px-4">
        <CardTitle>
          <h2>{title}</h2>
        </CardTitle>
        {href && (
          <CardAction>
            <Link
              href={href}
              className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm"
            >
              {linkLabel}
              <ArrowRight className="size-3.5" aria-hidden />
            </Link>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="px-4">{children}</CardContent>
    </Card>
  );
}

export function Muted({ children }: { children: ReactNode }) {
  return <p className="text-muted-foreground text-sm">{children}</p>;
}
