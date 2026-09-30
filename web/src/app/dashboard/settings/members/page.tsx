import type { Metadata } from "next";

import { SectionHeading } from "@/components/layout/page-header";
import { getMembers } from "@/lib/queries-members";
import { requireViewer } from "@/lib/viewer";

import { AddMemberButton } from "./add-member-dialog";
import { MembersTable } from "./members-table";

export const metadata: Metadata = { title: "Members" };

// Everyone who can sign in to this install. Members see the list;
// administrators manage it (docs/MEMBERS.md).
export default async function MembersPage() {
  const viewer = await requireViewer();
  const members = await getMembers();

  return (
    <div className="flex flex-col gap-4">
      <SectionHeading
        description={
          viewer.isAdmin
            ? "People who can sign in to this install. Administrators can change anything; members have read-only access."
            : "People who can sign in to this install. You have read-only access; ask an administrator to add or change members."
        }
        actions={viewer.isAdmin && <AddMemberButton />}
      >
        Members
      </SectionHeading>
      <MembersTable members={members} currentUserId={viewer.userId} />
    </div>
  );
}
