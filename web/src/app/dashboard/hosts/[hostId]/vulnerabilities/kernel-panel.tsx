import { Cpu, Info } from "lucide-react";
import Link from "next/link";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import type { KernelPackage } from "@/lib/queries-vulns";

// Installed kernels and whether findings cover them (running-kernel
// policy, DOMAIN_MODEL.md Q7): only the running kernel raises findings;
// when it's unknown, every installed kernel does.
export function KernelPanel({
  kernels,
  runningKernel,
  unknownFindings,
  packagesHref,
}: {
  kernels: KernelPackage[];
  runningKernel: string | null;
  unknownFindings: number;
  packagesHref: string;
}) {
  if (kernels.length === 0 && unknownFindings === 0) return null;
  const unknown = runningKernel === null;
  // One row per kernel release; image + modules packages are listed together.
  const releases = new Map<string, KernelPackage[]>();
  for (const k of kernels) {
    const list = releases.get(k.kernelRelease) ?? [];
    list.push(k);
    releases.set(k.kernelRelease, list);
  }

  return (
    <Alert>
      {unknown ? <Info className="size-4" /> : <Cpu className="size-4" />}
      <AlertTitle>
        {unknown ? (
          "Running kernel unknown"
        ) : (
          <>
            Running kernel <span className="font-mono">{runningKernel}</span>
          </>
        )}
      </AlertTitle>
      <AlertDescription className="flex flex-col gap-2">
        <p>
          {unknown
            ? "This agent hasn't reported which kernel is running (it predates the kernel collector, or the collector failed), so vulnerabilities are raised for every installed kernel below. Update the agent to narrow them to the running one."
            : "Kernel vulnerabilities are raised only for the running kernel. Other installed kernels are listed for information: their matches apply if the host boots into them."}
        </p>
        {releases.size > 0 && (
          <ul className="flex flex-col gap-1">
            {[...releases].map(([rel, pkgs]) => {
              const running = pkgs[0].isRunning;
              const vulns = Math.max(...pkgs.map((p) => p.vulnCount));
              const fixable = Math.max(...pkgs.map((p) => p.fixableCount));
              return (
                <li key={rel} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <span className="text-foreground font-mono text-xs">{rel}</span>
                  {running === true && <Badge variant="info">running</Badge>}
                  {running === false && <Badge variant="neutral">not running · info only</Badge>}
                  {running === null && <Badge variant="dashed">running state unknown</Badge>}
                  <span className="text-xs">
                    {vulns} known {vulns === 1 ? "vulnerability" : "vulnerabilities"}
                    {vulns > 0 && `, ${fixable} fixable`}
                    {" · "}
                    <Link
                      href={`${packagesHref}?q=${encodeURIComponent(pkgs[0].name)}`}
                      className="underline-offset-4 hover:underline"
                    >
                      {pkgs.map((p) => p.name).join(", ")}
                    </Link>
                  </span>
                </li>
              );
            })}
          </ul>
        )}
      </AlertDescription>
    </Alert>
  );
}
