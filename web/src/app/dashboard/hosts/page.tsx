import { redirect } from "next/navigation";

// The machine list is the Machines home page now; keep old links and
// bookmarks working, query string included.
export default async function HostsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(await searchParams)) {
    if (Array.isArray(value)) for (const v of value) params.append(key, v);
    else if (value !== undefined) params.append(key, value);
  }
  const qs = params.toString();
  redirect(qs ? `/dashboard?${qs}` : "/dashboard");
}
