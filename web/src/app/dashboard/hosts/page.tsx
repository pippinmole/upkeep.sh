import { redirect } from "next/navigation";

// Hosts are listed under the agent(s) that collect them on
// /dashboard/agents; there is no standalone host list yet.
export default function HostsIndexPage() {
  redirect("/dashboard/agents");
}
