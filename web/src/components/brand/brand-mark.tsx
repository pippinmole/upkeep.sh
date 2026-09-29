import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";

import { BRAND_MARKS, type BrandMarkName } from "./marks";

// Near-black brand colours (GitHub, AlmaLinux) would vanish in dark mode,
// so those stay currentColor even when `colored`.
function isTooDark(hex: string): boolean {
  const n = parseInt(hex, 16);
  const r = (n >> 16) & 0xff;
  const g = (n >> 8) & 0xff;
  const b = n & 0xff;
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 40;
}

// One Simple Icons brand mark. Monochrome (currentColor) by default, as in
// tables; `colored` uses the brand colour, for headers. `title` overrides
// the accessible name (defaults to the brand); pass title="" for a mark
// that sits next to its own text label, to hide it from assistive tech.
export function BrandMark({
  mark,
  size = 16,
  colored = false,
  className,
  title,
}: {
  mark: BrandMarkName;
  size?: number;
  colored?: boolean;
  className?: string;
  title?: string;
}) {
  const m = BRAND_MARKS[mark];
  const label = title ?? m.title;
  const fill = colored && !isTooDark(m.hex) ? `#${m.hex}` : "currentColor";
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill={fill}
      className={cn("shrink-0", className)}
      {...(label ? { role: "img", "aria-label": label } : { "aria-hidden": true })}
    >
      {label && <title>{label}</title>}
      <path d={m.path} />
    </svg>
  );
}

// A brand mark when there is one, else a lucide icon, with the same
// sizing and accessible-name rules as BrandMark. Shared by the wrappers.
export function MarkOrIcon({
  mark,
  fallback: Icon,
  size = 16,
  colored = false,
  className,
  title,
}: {
  mark: BrandMarkName | undefined;
  fallback: LucideIcon;
  size?: number;
  colored?: boolean;
  className?: string;
  title: string;
}) {
  if (mark) {
    return (
      <BrandMark mark={mark} size={size} colored={colored} className={className} title={title} />
    );
  }
  return (
    <Icon
      size={size}
      className={cn("shrink-0", className)}
      {...(title ? { role: "img", "aria-label": title } : { "aria-hidden": true })}
    />
  );
}
