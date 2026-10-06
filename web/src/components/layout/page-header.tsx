import Link from "next/link";
import { Fragment, type ReactNode } from "react";

import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { cn } from "@/lib/utils";

export type PageBreadcrumb = { label: ReactNode; href?: string };

// Every page's header and its only h1. Detail pages pass breadcrumbs (the
// last one is the current page); `meta` is a muted line of facts the caller
// separates itself.
export function PageHeader({
  breadcrumbs,
  title,
  icon,
  mono,
  badges,
  meta,
  description,
  actions,
  children,
  className,
}: {
  breadcrumbs?: PageBreadcrumb[];
  title: ReactNode;
  icon?: ReactNode;
  mono?: boolean;
  badges?: ReactNode;
  meta?: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
}) {
  return (
    <header className={cn("flex flex-col gap-2", className)}>
      {breadcrumbs && breadcrumbs.length > 0 && (
        <Breadcrumb>
          <BreadcrumbList>
            {breadcrumbs.map((b, i) => {
              const last = i === breadcrumbs.length - 1;
              return (
                <Fragment key={i}>
                  <BreadcrumbItem>
                    {last || !b.href ? (
                      <BreadcrumbPage>{b.label}</BreadcrumbPage>
                    ) : (
                      <BreadcrumbLink asChild>
                        <Link href={b.href}>{b.label}</Link>
                      </BreadcrumbLink>
                    )}
                  </BreadcrumbItem>
                  {!last && <BreadcrumbSeparator />}
                </Fragment>
              );
            })}
          </BreadcrumbList>
        </Breadcrumb>
      )}
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-3">
        <div className="flex min-w-0 flex-1 flex-col gap-1">
          <div className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-2">
            <div className="flex min-w-0 items-center gap-2">
              {icon && <span className="flex shrink-0 items-center [&>svg]:size-6">{icon}</span>}
              <h1
                className={cn(
                  "truncate text-2xl font-semibold tracking-tight",
                  mono && "font-mono",
                )}
              >
                {title}
              </h1>
            </div>
            {badges && <div className="flex flex-wrap items-center gap-1.5">{badges}</div>}
          </div>
          {meta && (
            <div className="text-muted-foreground flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
              {meta}
            </div>
          )}
          {description && <div className="text-muted-foreground text-sm">{description}</div>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2 sm:ml-auto">{actions}</div>}
      </div>
      {children}
    </header>
  );
}

// A section's h2, with an optional description under it. Actions sit on
// the title's row, right-aligned at every width, so a long description
// never pushes them onto a line of their own. The row is a button's height
// with or without actions, so headings line up from page to page.
export function SectionHeading({
  children,
  description,
  actions,
  className,
}: {
  children: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex min-w-0 flex-col gap-0.5", className)}>
      <div className="flex min-h-9 items-center justify-between gap-4">
        <h2 className="min-w-0 text-base font-semibold">{children}</h2>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {description && <SectionDescription>{description}</SectionDescription>}
    </div>
  );
}

// The muted line under a section's title, capped at a readable width. Also
// for a page under tabs, whose tab already names it.
export function SectionDescription({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <div className={cn("text-muted-foreground max-w-3xl text-sm", className)}>{children}</div>;
}
