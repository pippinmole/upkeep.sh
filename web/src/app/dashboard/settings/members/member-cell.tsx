import type { MemberRow } from "@/lib/queries-members";

// The Member column: username (and "(you)") over name and email. Name is
// left out when it's just the username (the server stores name || username).
export function MemberCell({ member, isYou }: { member: MemberRow; isYou: boolean }) {
  const username = member.username ?? member.email;
  const secondary =
    member.name && member.name !== username ? `${member.name} · ${member.email}` : member.email;
  return (
    <div className="flex max-w-72 min-w-0 flex-col lg:max-w-none" title={member.email}>
      <span className="truncate font-medium">
        {username}
        {isYou && <span className="text-muted-foreground ml-1.5 text-xs font-normal">(you)</span>}
      </span>
      <span className="text-muted-foreground truncate text-xs">{secondary}</span>
    </div>
  );
}
