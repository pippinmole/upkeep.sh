import { Info } from "lucide-react";

import type { DockerCoverage } from "@/lib/queries-docker-fleet";

function hostsWord(n: number): string {
  return `${n} host${n === 1 ? "" : "s"}`;
}

// Why a host isn't reporting Docker, from the newest snapshot's
// docker_images status (PROTOCOL.md "Docker sections": the reasons are
// exact strings).
function explain(status: string, reason: string | null, n: number): string {
  const hosts = hostsWord(n);
  if (status === "missing") {
    return `${hosts}: the agent doesn't report Docker (an older agent build, or no report yet).`;
  }
  if (status === "error") {
    return `${hosts}: Docker collection failed in the latest report.`;
  }
  switch (reason) {
    case "remote host":
      return `${hosts}: collected over SSH, which can only read files, not the Docker socket. Docker data needs an agent on the host itself.`;
    case "docker socket not mounted":
      return `${hosts}: Docker collection isn't enabled on the agent (the Docker socket isn't mounted into its container).`;
    case "docker engine unavailable":
      return `${hosts}: the Docker socket is mounted but the engine couldn't be used (refused, permission denied or too old an API).`;
    default:
      return `${hosts}: Docker collection skipped${reason ? ` (${reason})` : ""}.`;
  }
}

// Fleet pages list only what hosts report, so say which hosts can't
// report Docker at all: an empty list shouldn't read as "no containers".
export function DockerCoverageNote({ coverage }: { coverage: DockerCoverage }) {
  if (coverage.hosts === 0 || coverage.missing.length === 0) return null;
  return (
    <div className="bg-muted/40 text-muted-foreground flex gap-2 rounded-lg border px-4 py-3 text-sm">
      <Info className="mt-0.5 size-4 shrink-0" />
      <div className="flex flex-col gap-1">
        <p className="text-foreground">
          Docker data from {coverage.reporting} of {hostsWord(coverage.hosts)}.
          {coverage.reporting < coverage.hosts &&
            " Hosts not reporting keep their last known data, if any."}
        </p>
        <ul className="list-disc pl-4">
          {coverage.missing.map((m) => (
            <li key={`${m.status}:${m.reason ?? ""}`}>{explain(m.status, m.reason, m.hosts)}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}
