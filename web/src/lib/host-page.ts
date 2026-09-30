import { notFound, redirect } from "next/navigation";

import { auth } from "./auth";
import { osLabel as osNameVersion } from "./os";
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

export function osLabel(snap: HostDetail["latestSnapshot"]): string | null {
  if (!snap?.osId) return null;
  const codename = snap.osCodename ? ` (${snap.osCodename})` : "";
  return `${osNameVersion(snap.osId, snap.osVersionId)}${codename}`;
}

// PROTOCOL.md collector names -> human labels.
const COLLECTOR_LABELS: Record<string, string> = {
  os: "OS detection",
  host_identity: "Host identity",
  deb_packages: "Package inventory (deb)",
  tcp_listeners: "Listening ports (TCP)",
  udp_listeners: "Listening ports (UDP)",
  kernel: "Running kernel",
  uptime: "Uptime",
  arch: "Architecture",
  systemd_services: "Services (systemd)",
  local_users: "Local users",
  deleted_libs: "Processes on deleted libraries",
  unattended_upgrades: "Automatic updates",
  reboot_required: "Reboot-required check",
  public_ip: "Public IP lookup",
  docker_engine: "Docker engine",
  docker_containers: "Docker containers",
  docker_images: "Docker images",
  docker_networks: "Docker networks",
  swarm_services: "Swarm services",
  host_mount: "Agent host mount",
};

export function collectorLabel(name: string): string {
  return COLLECTOR_LABELS[name] ?? name;
}
