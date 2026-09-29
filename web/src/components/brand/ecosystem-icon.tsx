import { Package } from "lucide-react";

import { MarkOrIcon } from "./brand-mark";
import type { BrandMarkName } from "./marks";

// Package ecosystem → the distribution family's mark.
const ECOSYSTEM_MARKS: Record<string, BrandMarkName> = {
  deb: "debian",
  apk: "alpinelinux",
  rpm: "redhat",
};

const ECOSYSTEM_NAMES: Record<string, string> = {
  deb: "Debian package",
  apk: "Alpine package",
  rpm: "RPM package",
};

export function EcosystemIcon({
  ecosystem,
  size = 16,
  className,
}: {
  ecosystem: string;
  size?: number;
  className?: string;
}) {
  return (
    <MarkOrIcon
      mark={ECOSYSTEM_MARKS[ecosystem]}
      fallback={Package}
      size={size}
      className={className}
      title={ECOSYSTEM_NAMES[ecosystem] ?? `${ecosystem || "Unknown"} package`}
    />
  );
}
