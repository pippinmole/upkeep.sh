import { type LucideIcon, Monitor, Server } from "lucide-react";

import { osLabel, osName } from "@/lib/os";
import { cn } from "@/lib/utils";

import { MarkOrIcon } from "./brand-mark";
import type { BrandMarkName } from "./marks";

// os-release ID → brand mark. Ids without one (amzn, ol, sles, …) get a
// lucide fallback.
const OS_MARKS: Record<string, BrandMarkName> = {
  ubuntu: "ubuntu",
  debian: "debian",
  alpine: "alpinelinux",
  fedora: "fedora",
  rhel: "redhat",
  centos: "centos",
  rocky: "rockylinux",
  almalinux: "almalinux",
  arch: "archlinux",
  opensuse: "opensuse",
  "opensuse-leap": "opensuse",
  "opensuse-tumbleweed": "opensuse",
  linux: "linux",
};

const OS_FALLBACKS: Record<string, LucideIcon> = {
  windows: Monitor,
};

// An OS icon, optionally followed by "Name version". The icon carries the
// OS name as its accessible name, unless the label is shown.
export function OsLogo({
  osId,
  size = 16,
  colored = false,
  withLabel = false,
  version,
  className,
}: {
  osId: string | null | undefined;
  size?: number;
  colored?: boolean;
  withLabel?: boolean;
  version?: string | null;
  className?: string;
}) {
  const id = (osId ?? "").toLowerCase();
  const name = id ? osName(id) : "Unknown OS";
  const icon = (
    <MarkOrIcon
      mark={OS_MARKS[id]}
      fallback={OS_FALLBACKS[id] ?? Server}
      size={size}
      colored={colored}
      title={withLabel ? "" : name}
      className={withLabel ? undefined : className}
    />
  );
  if (!withLabel) return icon;
  return (
    <span className={cn("inline-flex items-center gap-1.5", className)}>
      {icon}
      <span>{osLabel(id, version) ?? name}</span>
    </span>
  );
}
