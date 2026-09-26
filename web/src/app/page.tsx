import Link from "next/link";

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-2xl flex-col justify-center gap-6 px-4 text-center">
      <h1 className="text-3xl font-semibold tracking-tight">security-whatnot</h1>
      <p className="text-lg text-neutral-600">
        Lightweight security monitoring for self-hosted VPSes. Not Wazuh, not Qualys — just the CVEs
        that are actually exploitable, the ports that just became public, and the reboots you keep
        putting off.
      </p>
      <div className="flex justify-center gap-4">
        <Link href="/signup" className="rounded bg-black px-4 py-2 text-white">
          Get started
        </Link>
        <Link href="/login" className="rounded border px-4 py-2">
          Sign in
        </Link>
      </div>
    </main>
  );
}
