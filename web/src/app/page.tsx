import { redirect } from "next/navigation";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { auth } from "@/lib/auth";

import { BrandMark } from "./login/auth-shell";

export default async function Home() {
  const session = await auth();
  if (session?.user?.id) redirect("/dashboard");

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
        <Button asChild size="lg">
          <Link href="/signup">Create account</Link>
        </Button>
        <Button asChild size="lg" variant="outline">
          <Link href="/login">Sign in</Link>
        </Button>
      </div>
    </main>
  );
}
