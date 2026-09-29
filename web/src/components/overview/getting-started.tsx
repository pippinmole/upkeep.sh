"use client";

import { CheckCircle2, Circle, Loader2 } from "lucide-react";
import Link from "next/link";
import { useSyncExternalStore } from "react";

import { Button } from "@/components/ui/button";
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import type { OnboardingState } from "@/lib/queries-onboarding";
import { cn } from "@/lib/utils";

// The Overview's first-run checklist (docs/design/ux-overhaul.md
// "Onboarding"). Shown until every required step is done; "Hide" is a
// per-browser convenience in localStorage, and the card renders normally
// when storage is unavailable.

const HIDDEN_KEY = "upkeep.onboarding.hidden";
const HIDDEN_EVENT = "upkeep:onboarding-hidden";

type Step = {
  key: keyof OnboardingState;
  title: string;
  description: string;
  action: { label: string; href: string };
  optional?: boolean;
};

const STEPS: Step[] = [
  {
    key: "agent",
    title: "Install an agent",
    description: "A small container that reports read-only facts about its machine, outbound only.",
    action: { label: "Add host", href: "/dashboard/hosts" },
  },
  {
    key: "hostReported",
    title: "First host reported",
    description: "The agent sends its first snapshot within a minute of starting.",
    action: { label: "View hosts", href: "/dashboard/hosts" },
  },
  {
    key: "docker",
    title: "Collect Docker",
    description: "Let the agent read the Docker socket to score your container images.",
    action: { label: "Set up Docker", href: "/dashboard/hosts" },
    optional: true,
  },
  {
    key: "channel",
    title: "Add a notification channel",
    description: "Where alerts and reports go: email, a webhook, ntfy and more.",
    action: { label: "Add channel", href: "/dashboard/settings/channels" },
  },
  {
    key: "rule",
    title: "Create an alert rule",
    description: "Choose which new findings and agent problems notify you.",
    action: { label: "Create rule", href: "/dashboard/alerts" },
  },
  {
    key: "report",
    title: "Schedule a report",
    description: "A weekly or monthly summary of what to patch first.",
    action: { label: "Schedule report", href: "/dashboard/reports" },
  },
];

function readHidden(): boolean {
  try {
    return window.localStorage.getItem(HIDDEN_KEY) === "1";
  } catch {
    return false;
  }
}

function subscribe(onChange: () => void) {
  window.addEventListener("storage", onChange);
  window.addEventListener(HIDDEN_EVENT, onChange);
  return () => {
    window.removeEventListener("storage", onChange);
    window.removeEventListener(HIDDEN_EVENT, onChange);
  };
}

function hide() {
  try {
    window.localStorage.setItem(HIDDEN_KEY, "1");
  } catch {
    // No storage: hidden for this page view only would need state; the
    // card simply stays. Nothing else depends on it.
  }
  window.dispatchEvent(new Event(HIDDEN_EVENT));
}

function onboardingComplete(state: OnboardingState): boolean {
  return STEPS.every((s) => s.optional || state[s.key]);
}

export function GettingStarted({ state }: { state: OnboardingState }) {
  const hidden = useSyncExternalStore(subscribe, readHidden, () => false);
  if (hidden || onboardingComplete(state)) return null;

  const done = STEPS.filter((s) => state[s.key]).length;
  const next = STEPS.find((s) => !s.optional && !state[s.key]);

  return (
    <Card className="gap-4">
      <CardHeader>
        <CardTitle>Getting started</CardTitle>
        <CardDescription>
          <span className="tabular-nums">
            {done} of {STEPS.length}
          </span>{" "}
          steps done
        </CardDescription>
        <CardAction>
          <Button variant="ghost" size="sm" onClick={hide}>
            Hide
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div
          role="progressbar"
          aria-label="Getting started progress"
          aria-valuemin={0}
          aria-valuemax={STEPS.length}
          aria-valuenow={done}
          className="bg-muted h-1.5 overflow-hidden rounded-full"
        >
          <div
            className="bg-success h-full rounded-full transition-[width]"
            style={{ width: `${(done / STEPS.length) * 100}%` }}
          />
        </div>
        <ol className="grid gap-x-6 gap-y-3 md:grid-cols-2 lg:grid-cols-3">
          {STEPS.map((s) => {
            const isDone = state[s.key];
            // The first snapshot follows the agent by itself: waiting, not todo.
            const inProgress = s.key === "hostReported" && !isDone && state.agent;
            const isNext = s === next;
            return (
              <li key={s.key} className="flex items-start gap-3">
                {isDone ? (
                  <CheckCircle2 className="text-success mt-0.5 size-5 shrink-0" aria-hidden />
                ) : inProgress ? (
                  <Loader2
                    className="text-muted-foreground mt-0.5 size-5 shrink-0 animate-spin motion-reduce:animate-none"
                    aria-hidden
                  />
                ) : (
                  <Circle className="text-muted-foreground mt-0.5 size-5 shrink-0" aria-hidden />
                )}
                <div className="flex min-w-0 flex-col gap-1">
                  <p className={cn("text-sm font-medium", isDone && "text-muted-foreground")}>
                    {s.title}
                    {s.optional && (
                      <span className="text-muted-foreground font-normal"> (optional)</span>
                    )}
                    <span className="sr-only">
                      {isDone ? " (done)" : inProgress ? " (waiting)" : " (to do)"}
                    </span>
                  </p>
                  {!isDone && <p className="text-muted-foreground text-sm">{s.description}</p>}
                  {isNext && !inProgress && (
                    <Button asChild size="sm" className="mt-1 self-start">
                      <Link href={s.action.href}>{s.action.label}</Link>
                    </Button>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      </CardContent>
    </Card>
  );
}
