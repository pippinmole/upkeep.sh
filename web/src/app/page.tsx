import { redirect } from "next/navigation";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { installHasUsers } from "@/lib/auth";
import { getViewer } from "@/lib/viewer";

import { BrandMark } from "./login/auth-shell";

export default async function Home() {
  if (await getViewer()) redirect("/dashboard");
  // Sign-up only creates the first (administrator) account.
  const bootstrapping = !(await installHasUsers());

  return (
    <main className="bg-background flex min-h-screen flex-col items-center justify-center gap-8 px-4 py-12 text-center">
      <BrandMark />
      <div className="flex max-w-2xl flex-col gap-4">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">
          Security upkeep for self-hosted servers
        </h1>
        <p className="text-muted-foreground text-lg">
          Lightweight monitoring for your VPSes. Not Wazuh, not Qualys: just the CVEs that are
          actually exploitable, the ports that just became public, and the reboots you keep putting
          off.
        </p>
      </div>
      <div className="flex flex-wrap justify-center gap-3">
        {bootstrapping && (
          <Button asChild size="lg">
            <Link href="/signup">Create account</Link>
          </Button>
        )}
        <Button asChild size="lg" variant={bootstrapping ? "outline" : "default"}>
          <Link href="/login">Sign in</Link>
        </Button>
      </div>
    </main>
  );
}
