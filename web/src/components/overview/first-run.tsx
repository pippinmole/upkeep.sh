import { Container, Radar, ShieldCheck } from "lucide-react";
import Link from "next/link";

import { AddHostDialog } from "@/app/dashboard/hosts/add-host-dialog";
import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import type { CollectorAgent } from "@/lib/queries-remote";

import { AutoRefresh } from "./auto-refresh";

// What the Overview shows before any host has reported: a Getting-started
// hero instead of a wall of zeros, then a waiting state until the first
// snapshot arrives.

const STEPS = [
  {
    icon: Container,
    title: "Install an agent",
    body: "A small container that reads the machine and reports read-only facts, outbound only. Nothing listens on the host.",
  },
  {
    icon: Radar,
    title: "It reports its host",
    body: "The agent sends its first snapshot within a minute of starting.",
  },
  {
    icon: ShieldCheck,
    title: "See what needs fixing",
    body: "Vulnerabilities, open ports and pending reboots show up here, most urgent first.",
  },
];

export function FirstRunHero({
  serverUrl,
  agents,
}: {
  serverUrl: string;
  agents: CollectorAgent[];
}) {
  return (
    <Card className="gap-8 py-8">
      <CardHeader className="px-6 sm:px-8">
        <CardTitle className="text-xl">Let&apos;s connect your first server</CardTitle>
        <CardDescription className="max-w-2xl">
          upkeep watches your servers through a lightweight agent. Three steps and you&apos;re set.
        </CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-8 px-6 sm:px-8">
        <ol className="grid gap-6 md:grid-cols-3">
          {STEPS.map((s, i) => (
            <li key={s.title} className="flex gap-3">
              <span className="bg-primary text-primary-foreground flex size-7 shrink-0 items-center justify-center rounded-full text-sm font-semibold tabular-nums">
                {i + 1}
              </span>
              <div className="flex flex-col gap-1">
                <p className="flex items-center gap-2 font-medium">
                  <s.icon className="text-muted-foreground size-4" aria-hidden />
                  {s.title}
                </p>
                <p className="text-muted-foreground text-sm">{s.body}</p>
              </div>
            </li>
          ))}
        </ol>
        <div className="flex flex-wrap items-center gap-2">
          <AddHostDialog serverUrl={serverUrl} agents={agents} />
          <Button asChild variant="ghost">
            <Link href="/dashboard/agents">What&apos;s an agent?</Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// Agents or hosts exist, but no snapshot yet. `names` are the agents (or
// hosts) we are waiting on.
export function WaitingForFirstReport({ names }: { names: string[] }) {
  const who =
    names.length === 0
      ? "your agent"
      : names.length <= 2
        ? names.join(" and ")
        : `${names.slice(0, 2).join(", ")} and ${names.length - 2} more`;
  return (
    <>
      <AutoRefresh />
      <EmptyState
        size="page"
        loading
        title={`Waiting for the first report from ${who}`}
        description="Agents report within a minute of starting. This page updates by itself when the first snapshot arrives."
        action={
          <Button asChild variant="outline">
            <Link href="/dashboard/agents">Check agents</Link>
          </Button>
        }
      />
    </>
  );
}
