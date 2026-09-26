import { redirect } from "next/navigation";

// The host list still lives at /dashboard/agents until the agent/host
// split (DOMAIN_MODEL.md §4) renames it to Hosts.
export default function HostsIndexPage() {
  redirect("/dashboard/agents");
}
