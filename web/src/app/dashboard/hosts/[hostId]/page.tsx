import type { Metadata } from "next";
import Link from "next/link";

import { hostTitle, requireHost } from "@/lib/host-page";
import { formatDateTime, relativeTime } from "@/lib/time";

import { SystemOverview } from "./system-overview";

type Params = Promise<{ hostId: string }>;

export async function generateMetadata({ params }: { params: Params }): Promise<Metadata> {
  const { host } = await requireHost((await params).hostId);
  return { title: hostTitle(host) };
}

// Minimal overview: inventory freshness per package source and reboot
// state. Vulnerability stat cards arrive with P1b.
export default async function HostOverviewPage({ params }: { params: Params }) {
  const { userId, host } = await requireHost((await params).hostId);
  const snap = host.latestSnapshot;
  const base = `/dashboard/hosts/${host.id}`;

  return (
    <div className="grid gap-4 md:grid-cols-2">
      <section className="bg-card rounded-lg border p-4">
        <h2 className="font-semibold">Package inventory</h2>
        {host.inventory.length === 0 ? (
          <p className="text-muted-foreground mt-2 text-sm">
            No package inventory has been recorded for this host yet.
          </p>
        ) : (
          <dl className="mt-3 space-y-3 text-sm">
            {host.inventory.map((inv) => (
              <div key={inv.ecosystem}>
                <dt className="font-medium">
                  <Link
                    href={`${base}/packages?ecosystem=${encodeURIComponent(inv.ecosystem)}`}
                    className="hover:underline"
                  >
                    {inv.openPackages.toLocaleString("en-GB")} {inv.ecosystem} packages
                  </Link>
                </dt>
                <dd className="text-muted-foreground">
                  Confirmed{" "}
                  <span title={formatDateTime(inv.confirmedAt)}>
                    {relativeTime(inv.confirmedAt)}
                  </span>{" "}
                  · last changed{" "}
                  <Link href={`${base}/history`} className="hover:underline">
                    <span title={formatDateTime(inv.changedAt)}>{relativeTime(inv.changedAt)}</span>
                  </Link>
                </dd>
              </div>
            ))}
          </dl>
        )}
      </section>

      <section className="bg-card rounded-lg border p-4">
        <h2 className="font-semibold">Reboot</h2>
        {!snap ? (
          <p className="text-muted-foreground mt-2 text-sm">No snapshots yet.</p>
        ) : snap.rebootRequired ? (
          <div className="mt-2 text-sm">
            <p>A reboot is required.</p>
            {snap.rebootPackages.length > 0 && (
              <p className="text-muted-foreground mt-1">
                Requested by:{" "}
                <span className="font-mono text-xs">{snap.rebootPackages.join(", ")}</span>
              </p>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground mt-2 text-sm">No reboot pending.</p>
        )}
        <p className="text-muted-foreground mt-3 text-xs">
          Registered {formatDateTime(host.createdAt)}
        </p>
      </section>

      <SystemOverview userId={userId} hostId={host.id} />
    </div>
  );
}
