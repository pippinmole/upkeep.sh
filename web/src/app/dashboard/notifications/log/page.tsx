import { ScrollText } from "lucide-react";
import type { Metadata } from "next";
import { redirect } from "next/navigation";

import { auth } from "@/lib/auth";
import { getDeliveries } from "@/lib/queries-notifications";

import { DeliveriesTable } from "./deliveries-table";

export const metadata: Metadata = { title: "Delivery log" };

const LIMIT = 500;

export default async function DeliveryLogPage() {
  const session = await auth();
  if (!session?.user?.id) redirect("/login");
  const deliveries = await getDeliveries(session.user.id, LIMIT);

  return (
    <div className="flex flex-col gap-4">
      <p className="text-muted-foreground text-sm">
        Every notification sent to each channel, with each attempt&apos;s response. Failed attempts
        are retried with backoff for about 11 hours. The newest {LIMIT} are shown; the log keeps 90
        days.
      </p>
      {deliveries.length === 0 ? (
        <div className="border-border bg-card flex flex-col items-center gap-3 rounded-lg border border-dashed px-6 py-16 text-center">
          <ScrollText className="text-muted-foreground size-8" />
          <div>
            <h2 className="font-semibold">Nothing sent yet</h2>
            <p className="text-muted-foreground mt-1 max-w-sm text-sm">
              Deliveries show up here once a rule matches, or when you send a test from the Channels
              tab.
            </p>
          </div>
        </div>
      ) : (
        <DeliveriesTable deliveries={deliveries} />
      )}
    </div>
  );
}
