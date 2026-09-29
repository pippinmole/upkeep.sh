import { CheckCircle2, Loader2, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

// The one empty state: what's missing, why, and the action that fixes it.
// `steps` lists prerequisites in order; `loading` is for "waiting for data"
// states that resolve by themselves (e.g. the first snapshot).

export type EmptyStateStep = { label: ReactNode; done: boolean };

const ICON_TONE = {
  default: "bg-muted text-muted-foreground",
  warning: "bg-warning/10 text-warning-fg",
  info: "bg-info/10 text-info-fg",
};

const SIZE = {
  page: { root: "gap-4 px-6 py-16", icon: "size-12 [&>svg]:size-6", title: "text-lg" },
  section: { root: "gap-3 px-6 py-10", icon: "size-10 [&>svg]:size-5", title: "text-base" },
  inline: { root: "gap-2 px-4 py-6", icon: "size-8 [&>svg]:size-4", title: "text-sm" },
};

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  secondaryAction,
  steps,
  variant = "default",
  size = "section",
  loading = false,
  className,
  children,
}: {
  icon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  secondaryAction?: ReactNode;
  steps?: EmptyStateStep[];
  variant?: "default" | "warning" | "info";
  size?: "page" | "section" | "inline";
  loading?: boolean;
  className?: string;
  children?: ReactNode;
}) {
  const s = SIZE[size];
  const showIcon = loading || Icon;
  return (
    <div
      role={loading ? "status" : undefined}
      className={cn(
        "flex flex-col items-center justify-center rounded-lg border border-dashed text-center",
        variant === "warning" && "border-warning/40",
        s.root,
        className,
      )}
    >
      {showIcon && (
        <div
          className={cn(
            "flex shrink-0 items-center justify-center rounded-full",
            ICON_TONE[variant],
            s.icon,
          )}
        >
          {loading ? (
            <Loader2 className="animate-spin" aria-hidden />
          ) : (
            Icon && <Icon aria-hidden />
          )}
        </div>
      )}
      <div className="flex max-w-md flex-col gap-1">
        <p className={cn("font-semibold", s.title)}>{title}</p>
        {description && <div className="text-muted-foreground text-sm">{description}</div>}
      </div>
      {steps && steps.length > 0 && (
        <ol className="flex flex-col gap-1.5 text-left text-sm">
          {steps.map((step, i) => (
            <li key={i} className="flex items-center gap-2">
              {step.done ? (
                <CheckCircle2 className="text-success size-4 shrink-0" aria-hidden />
              ) : (
                <span
                  aria-hidden
                  className="text-muted-foreground flex size-4 shrink-0 items-center justify-center rounded-full border text-[10px] tabular-nums"
                >
                  {i + 1}
                </span>
              )}
              <span className={cn(step.done && "text-muted-foreground line-through")}>
                {step.label}
              </span>
              {step.done && <span className="sr-only">(done)</span>}
            </li>
          ))}
        </ol>
      )}
      {children}
      {(action || secondaryAction) && (
        <div className="flex flex-wrap items-center justify-center gap-2">
          {action}
          {secondaryAction}
        </div>
      )}
    </div>
  );
}
