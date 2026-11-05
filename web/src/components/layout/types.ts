import type { Role } from "@/lib/roles";

interface User {
  name: string;
  email: string;
  role: Role;
}

// What the top bar shows (lib/queries-nav.ts): the workspace name, the
// firing-alerts badge, and whether the Swarm link shows in the command menu.
type TopBarData = {
  workspaceName: string;
  firingAlerts: number;
  hasSwarm: boolean;
};

export type { TopBarData, User };
