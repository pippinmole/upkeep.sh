import { CommandMenu } from "@/components/command-menu";
import { TopBar } from "@/components/layout/top-bar";
import { ViewerProvider } from "@/components/viewer-context";
import { getTopBarData } from "@/lib/queries-nav";
import { requireViewer } from "@/lib/viewer";

interface Props {
  children: React.ReactNode;
}

export default async function DashboardLayout({ children }: Props) {
  // Signed out, disabled, or still on a temporary password: redirected here,
  // before anything renders.
  const viewer = await requireViewer();

  const user = {
    name: viewer.name || viewer.username || viewer.email.split("@")[0] || viewer.email,
    email: viewer.email,
    role: viewer.role,
  };
  const data = await getTopBarData(viewer.workspaceId);

  return (
    <ViewerProvider role={viewer.role}>
      <TopBar data={data} user={user} />
      {/* The top bar's skip link lands here. */}
      <div id="content" tabIndex={-1} className="flex w-full min-w-0 flex-1 flex-col outline-none">
        {children}
      </div>
      <CommandMenu hasSwarm={data.hasSwarm} />
    </ViewerProvider>
  );
}
