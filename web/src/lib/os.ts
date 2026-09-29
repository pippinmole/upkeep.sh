// OS display names, keyed by os-release ID (the agent's `os` collector).
// The one place OS names live; client-safe (no database imports).

export const OS_NAMES: Record<string, string> = {
  ubuntu: "Ubuntu",
  debian: "Debian",
  alpine: "Alpine Linux",
  fedora: "Fedora",
  rhel: "RHEL",
  centos: "CentOS",
  rocky: "Rocky Linux",
  almalinux: "AlmaLinux",
  ol: "Oracle Linux",
  arch: "Arch Linux",
  amzn: "Amazon Linux",
  opensuse: "openSUSE",
  "opensuse-leap": "openSUSE Leap",
  "opensuse-tumbleweed": "openSUSE Tumbleweed",
  sles: "SUSE Linux Enterprise",
  windows: "Windows",
};

// "ubuntu" → "Ubuntu"; unknown ids are shown as reported.
export function osName(id: string): string {
  return OS_NAMES[id] ?? id;
}

// "Ubuntu 24.04", or just the name without a version. Null/empty id → null.
export function osLabel(id: string | null | undefined, version?: string | null): string | null {
  if (!id) return null;
  return version ? `${osName(id)} ${version}` : osName(id);
}
