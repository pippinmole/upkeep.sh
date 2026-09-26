import { notFound, redirect } from "next/navigation";

import { auth } from "./auth";
import { getHost, type HostDetail } from "./queries-inventory";

// Auth + ownership gate for every /dashboard/hosts/[hostId] layout and page.
// Layouts don't re-render on client navigation between tabs, so each page
// must call this itself rather than relying on the layout's check.
// getHost is React-cached, so layout + page share one query per request.
export async function requireHost(hostId: string): Promise<{ userId: string; host: HostDetail }> {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const host = await getHost(session.user.id, hostId);
  if (!host) notFound();
  return { userId: session.user.id, host };
}

export function hostTitle(host: Pick<HostDetail, "hostname" | "label">) {
  return host.label ? `${host.label} (${host.hostname})` : host.hostname;
}

const OS_NAMES: Record<string, string> = {
  ubuntu: "Ubuntu",
  debian: "Debian",
  alpine: "Alpine",
  fedora: "Fedora",
  rhel: "RHEL",
  centos: "CentOS",
  rocky: "Rocky Linux",
  almalinux: "AlmaLinux",
  arch: "Arch Linux",
};

export function osLabel(snap: HostDetail["latestSnapshot"]): string | null {
  if (!snap?.osId) return null;
  const name = OS_NAMES[snap.osId] ?? snap.osId;
  const version = snap.osVersionId ? ` ${snap.osVersionId}` : "";
  const codename = snap.osCodename ? ` (${snap.osCodename})` : "";
  return `${name}${version}${codename}`;
}

// PROTOCOL.md collector names -> human labels.
const COLLECTOR_LABELS: Record<string, string> = {
  os: "OS detection",
  host_identity: "Host identity",
  deb_packages: "Package inventory (deb)",
  tcp_listeners: "Listening ports",
  reboot_required: "Reboot-required check",
  public_ip: "Public IP lookup",
};

export function collectorLabel(name: string): string {
  return COLLECTOR_LABELS[name] ?? name;
}
