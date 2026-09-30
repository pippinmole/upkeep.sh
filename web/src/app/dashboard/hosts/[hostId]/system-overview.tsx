import { formatUptime, getHostSystem } from "@/lib/queries-host-facts";
import { formatDateTime, relativeTime } from "@/lib/time";

import { Muted, OverviewCard } from "./overview-card";

// Overview sections for the Linux breadth facts: system (uptime, arch,
// automatic updates) and "needs restart" (processes on deleted libraries).
// Server component; getHostSystem is scoped by workspaceId.
export async function SystemOverview({
  workspaceId,
  hostId,
}: {
  workspaceId: string;
  hostId: string;
}) {
  const sys = await getHostSystem(workspaceId, hostId);
  if (!sys) return null;
  const uu = sys.unattendedUpgrades;
  const nr = sys.needsRestart;

  return (
    <>
      <OverviewCard title="System">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Uptime</dt>
          <dd>
            {sys.uptimeSeconds !== null ? (
              <span title={sys.bootedAt ? `Booted ${formatDateTime(sys.bootedAt)}` : undefined}>
                {formatUptime(sys.uptimeSeconds)}
                <span className="text-muted-foreground"> at last snapshot</span>
              </span>
            ) : (
              <span className="text-muted-foreground">Unknown</span>
            )}
          </dd>
          <dt className="text-muted-foreground">Architecture</dt>
          <dd className="font-mono">
            {sys.arch ?? <span className="text-muted-foreground font-sans">Unknown</span>}
          </dd>
          <dt className="text-muted-foreground">Automatic updates</dt>
          <dd>
            {!uu ? (
              <span className="text-muted-foreground">Not reported</span>
            ) : uu.enabled ? (
              <span className="text-success-fg">unattended-upgrades enabled</span>
            ) : (
              <span className="text-warning-fg">
                {uu.package_installed === false
                  ? "unattended-upgrades not installed"
                  : "unattended-upgrades disabled"}
              </span>
            )}
          </dd>
          {uu && (
            <>
              <dt className="text-muted-foreground">Last apt update</dt>
              <dd>
                {uu.last_apt_update ? (
                  <span
                    title={`${formatDateTime(uu.last_apt_update)} (${
                      uu.last_apt_update_source === "lists"
                        ? "package lists modified"
                        : "APT update-success stamp"
                    })`}
                  >
                    {relativeTime(uu.last_apt_update)}
                  </span>
                ) : (
                  <span className="text-muted-foreground">Unknown</span>
                )}
                {uu.last_unattended_run && (
                  <span
                    className="text-muted-foreground"
                    title={formatDateTime(uu.last_unattended_run)}
                  >
                    {" "}
                    · unattended run {relativeTime(uu.last_unattended_run)}
                  </span>
                )}
              </dd>
            </>
          )}
        </dl>
      </OverviewCard>

      <OverviewCard title="Needs restart" className="md:col-span-2">
        {!nr ? (
          <Muted>
            Not reported (older agent, or the agent can&apos;t read this host&apos;s processes).
          </Muted>
        ) : nr.processes.length === 0 ? (
          <Muted>No process is running a deleted (upgraded) shared library.</Muted>
        ) : (
          <>
            <Muted>
              {nr.processes.length}
              {nr.truncated ? "+" : ""} {nr.processes.length === 1 ? "process is" : "processes are"}{" "}
              still running code from libraries replaced by an upgrade. Restart them (or reboot) for
              the fix to take effect.
            </Muted>
            <ul className="mt-3 space-y-2 text-sm">
              {nr.processes.map((p) => (
                <li key={p.pid}>
                  <span className="font-medium">{p.unit ?? p.name}</span>{" "}
                  <span className="text-muted-foreground font-mono text-xs">
                    {p.unit ? `${p.name} ` : ""}pid {p.pid}
                  </span>
                  <div className="text-muted-foreground font-mono text-xs break-all">
                    {p.libraries.join(", ")}
                  </div>
                </li>
              ))}
            </ul>
          </>
        )}
        {nr && nr.unreadable_processes > 0 && (
          <p className="text-muted-foreground mt-3 text-xs">
            {nr.unreadable_processes} processes owned by other users couldn&apos;t be checked (the
            agent runs without ptrace access).
          </p>
        )}
      </OverviewCard>
    </>
  );
}
