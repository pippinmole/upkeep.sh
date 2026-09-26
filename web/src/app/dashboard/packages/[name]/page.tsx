import { ArrowLeft } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { redirect } from "next/navigation";

import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { auth } from "@/lib/auth";
import { getFleetPackage } from "@/lib/queries-inventory";
import { formatDate, formatDateTime } from "@/lib/time";

type Params = Promise<{ name: string }>;

// Route params arrive percent-decoded; cap length since it's a bound
// parameter compared by equality anyway.
async function packageName(params: Params): Promise<string> {
  return (await params).name.slice(0, 200);
}

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  return { title: `${await packageName(params)} · Packages` };
}

function release(distro: string, rel: string): string {
  return [distro, rel].filter(Boolean).join(" ") || "—";
}

function HostLink({
  id,
  hostname,
  label,
  name,
}: {
  id: string;
  hostname: string;
  label: string | null;
  name: string;
}) {
  return (
    <Link
      href={`/dashboard/hosts/${id}/packages?q=${encodeURIComponent(name)}`}
      className="font-medium hover:underline"
    >
      {label ? `${label} (${hostname})` : hostname}
    </Link>
  );
}

export default async function FleetPackagePage({ params }: { params: Params }) {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const name = await packageName(params);

  const { versions, hosts, formerHosts } = await getFleetPackage(session.user.id, name);
  const hostCount = new Set(hosts.map((h) => h.hostId)).size;

  return (
    <main className="flex min-h-0 flex-1 flex-col gap-6 p-4 sm:p-6">
      <div>
        <Link
          href="/dashboard/packages"
          className="text-muted-foreground hover:text-foreground inline-flex items-center gap-1 text-sm"
        >
          <ArrowLeft className="size-3.5" />
          All packages
        </Link>
        <h1 className="mt-2 font-mono text-2xl font-bold">{name}</h1>
        <p className="text-muted-foreground text-sm">
          {hostCount === 0
            ? "Not currently installed on any of your hosts."
            : `Installed on ${hostCount} host${hostCount === 1 ? "" : "s"} in ${versions.length} version${versions.length === 1 ? "" : "s"}.`}
        </p>
      </div>

      {versions.length > 0 && (
        <section className="flex flex-col gap-2">
          <h2 className="font-semibold">Versions</h2>
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Version</TableHead>
                  <TableHead>Release</TableHead>
                  <TableHead>Arch</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Ecosystem</TableHead>
                  {/* P1b: vulnerabilities, "Fixed in" */}
                  <TableHead className="text-right">Hosts</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {versions.map((v) => (
                  <TableRow key={`${v.ecosystem}:${v.distro}:${v.release}:${v.version}:${v.arch}`}>
                    <TableCell className="font-mono text-xs">{v.version}</TableCell>
                    <TableCell className="text-muted-foreground">
                      {release(v.distro, v.release)}
                    </TableCell>
                    <TableCell className="text-muted-foreground">{v.arch || "—"}</TableCell>
                    <TableCell className="text-muted-foreground text-xs">
                      {v.sourceName ? (
                        <>
                          {v.sourceName}{" "}
                          {v.sourceVersion && v.sourceVersion !== v.version && (
                            <span className="font-mono">{v.sourceVersion}</span>
                          )}
                        </>
                      ) : (
                        "—"
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-normal">
                        {v.ecosystem}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right tabular-nums">{v.hosts}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {hosts.length > 0 && (
        <section className="flex flex-col gap-2">
          <h2 className="font-semibold">Hosts with {name} installed</h2>
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Release</TableHead>
                  <TableHead>Installed version</TableHead>
                  <TableHead>Arch</TableHead>
                  <TableHead>Since</TableHead>
                  {/* P1b: Status */}
                </TableRow>
              </TableHeader>
              <TableBody>
                {hosts.map((h) => (
                  <TableRow key={`${h.hostId}:${h.ecosystem}:${h.version}:${h.arch}`}>
                    <TableCell>
                      <HostLink id={h.hostId} hostname={h.hostname} label={h.label} name={name} />
                    </TableCell>
                    <TableCell className="text-muted-foreground">
                      {release(h.distro, h.release)}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{h.version}</TableCell>
                    <TableCell className="text-muted-foreground">{h.arch || "—"}</TableCell>
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      <span title={formatDateTime(h.since)}>{formatDate(h.since)}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {formerHosts.length > 0 && (
        <section className="flex flex-col gap-2">
          <h2 className="font-semibold">Previously installed</h2>
          <p className="text-muted-foreground -mt-1 text-sm">
            Hosts that had {name} at some point but no longer do.
          </p>
          <div className="bg-card rounded-lg border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead>Last version</TableHead>
                  <TableHead>Arch</TableHead>
                  <TableHead>Removed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {formerHosts.map((h) => (
                  <TableRow key={h.hostId}>
                    <TableCell>
                      <Link
                        href={`/dashboard/hosts/${h.hostId}/history`}
                        className="font-medium hover:underline"
                      >
                        {h.label ? `${h.label} (${h.hostname})` : h.hostname}
                      </Link>
                    </TableCell>
                    <TableCell className="font-mono text-xs">{h.lastVersion}</TableCell>
                    <TableCell className="text-muted-foreground">{h.arch || "—"}</TableCell>
                    <TableCell className="text-muted-foreground whitespace-nowrap">
                      <span title={formatDateTime(h.removedAt)}>{formatDate(h.removedAt)}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}

      {hosts.length === 0 && formerHosts.length === 0 && (
        <div className="bg-card text-muted-foreground rounded-lg border px-6 py-12 text-center text-sm">
          None of your hosts has ever reported a package named{" "}
          <span className="font-mono">{name}</span>.
        </div>
      )}
    </main>
  );
}
