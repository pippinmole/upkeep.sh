import { AlertTriangle } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { collectorLabel } from "@/lib/host-page";
import type { CollectorStatus } from "@/lib/queries-inventory";

import { CollectorFailureMessage } from "./collector-failure-message";

// The host page's warning for collectors that reported `error` in the
// latest snapshot: one row per collector, its label over its message.
export function CollectorFailures({ errors }: { errors: [string, CollectorStatus][] }) {
  if (errors.length === 0) return null;
  // A failed package source makes the inventory tabs stale, so that one is
  // red; other collector failures are a softer warning.
  const packagesFailed = errors.some(([name]) => name.endsWith("_packages"));

  return (
    <Alert variant={packagesFailed ? "destructive" : "default"}>
      <AlertTriangle className={packagesFailed ? "size-4" : "text-warning-fg! size-4"} />
      <AlertTitle>
        {errors.length === 1
          ? "A collector failed in the latest snapshot"
          : `${errors.length} collectors failed in the latest snapshot`}
      </AlertTitle>
      <AlertDescription>
        <ul className="mt-3 flex flex-col divide-y border-t">
          {errors.map(([name, s]) => (
            <CollectorFailureRow key={name} name={name} error={s.error} />
          ))}
        </ul>
        {packagesFailed && (
          <p className="mt-2.5 border-t pt-2.5">
            The package list below is the last successfully collected inventory, not an empty one.
          </p>
        )}
      </AlertDescription>
    </Alert>
  );
}

function CollectorFailureRow({ name, error }: { name: string; error?: string }) {
  const label = collectorLabel(name);
  return (
    <li className="flex flex-col gap-1 py-2.5 last:pb-0">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
        <span className="text-foreground font-medium">{label}</span>
        {label !== name && (
          <span className="text-muted-foreground font-mono text-xs" title="Collector name">
            {name}
          </span>
        )}
      </div>
      {error?.trim() ? (
        <CollectorFailureMessage error={error} />
      ) : (
        <p className="text-muted-foreground">No error message was reported.</p>
      )}
    </li>
  );
}
