import { auth } from "@/lib/auth";
import { getHostsForUser } from "@/lib/queries";
import { AddHostButton } from "./add-host-button";

export default async function DashboardPage() {
  const session = await auth();
  if (!session?.user?.id) return null; // middleware already redirects

  const hosts = await getHostsForUser(session.user.id);
  const serverUrl = process.env.PUBLIC_API_URL ?? "https://your-instance.example.com";

  return (
    <main className="mx-auto max-w-3xl px-4 py-10">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Hosts</h1>
        <AddHostButton serverUrl={serverUrl} />
      </div>

      {hosts.length === 0 ? (
        <p className="text-neutral-500">
          No hosts yet. Click &ldquo;Add host&rdquo; to enroll your first server.
        </p>
      ) : (
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b text-neutral-500">
              <th className="py-2">Host</th>
              <th className="py-2">Last seen</th>
              <th className="py-2">Open findings</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.id} className="border-b">
                <td className="py-2">{h.label ?? h.hostname}</td>
                <td className="py-2">
                  {h.lastSeenAt ? new Date(h.lastSeenAt).toLocaleString() : "never"}
                </td>
                <td className="py-2">{h.openFindings}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
