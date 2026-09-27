import type { Metadata } from "next";

import { hostTitle, requireHost } from "@/lib/host-page";
import { getHostUsers } from "@/lib/queries-host-facts";

import { FactFreshnessNote } from "../fact-freshness";
import { UsersTable } from "./users-table";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: `Users · ${hostTitle(host)}` };
}

// Local accounts (open host_users ranges) from /etc/passwd + /etc/group.
// Directory-service (LDAP/SSSD) accounts aren't visible to the agent.
export default async function HostUsersPage({ params }: { params: Params }) {
  const { userId, host } = await requireHost((await params).hostId);
  const { rows, freshness } = await getHostUsers(userId, host.id);
  const interactive = rows.filter((r) => r.loginShell).length;
  const admins = rows.filter((r) => r.admin).length;

  return (
    <div className="flex flex-col gap-3">
      <div>
        <h2 className="font-semibold">
          Local users{" "}
          {rows.length > 0 && (
            <span className="text-muted-foreground text-sm font-normal">
              {rows.length} accounts, {interactive} with a login shell, {admins} admin
            </span>
          )}
        </h2>
        <FactFreshnessNote label="users" freshness={freshness} />
      </div>
      {rows.length > 0 && <UsersTable rows={rows} />}
    </div>
  );
}
