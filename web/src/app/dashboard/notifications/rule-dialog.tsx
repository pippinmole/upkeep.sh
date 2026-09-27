"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { useState, useTransition } from "react";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  channelType,
  DEDUP_WINDOWS,
  DIGEST_INTERVALS,
  durationLabel,
  EVENT_TYPES,
  eventTypeLabel,
  isFindingEvent,
  SEVERITY_FLOORS,
} from "@/lib/notifiers";
import type { ChannelRow, RuleRow, ScopeHost } from "@/lib/queries-notifications";

import { createRule, type RuleInput, updateRule } from "./actions";

function Err({ msg }: { msg?: string }) {
  return msg ? <p className="text-destructive text-xs">{msg}</p> : null;
}

function CheckList<T>({
  items,
  selected,
  onToggle,
  id,
  label,
}: {
  items: T[];
  selected: string[];
  onToggle: (key: string) => void;
  id: (t: T) => string;
  label: (t: T) => React.ReactNode;
}) {
  return (
    <div className="max-h-40 overflow-y-auto rounded-md border p-2">
      {items.map((t) => (
        <label key={id(t)} className="flex items-center gap-2 py-1 text-sm">
          <input
            type="checkbox"
            className="accent-primary size-4"
            checked={selected.includes(id(t))}
            onChange={() => onToggle(id(t))}
          />
          {label(t)}
        </label>
      ))}
    </div>
  );
}

const toggle = (list: string[], v: string) =>
  list.includes(v) ? list.filter((x) => x !== v) : [...list, v];

export function RuleDialog({
  open,
  onOpenChange,
  rule,
  channels,
  hosts,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule?: RuleRow;
  channels: ChannelRow[];
  hosts: ScopeHost[];
}) {
  const [v, setV] = useState<RuleInput>({
    name: rule?.name ?? "",
    eventTypes: rule?.eventTypes ?? ["finding.opened"],
    minSeverityRank: rule?.minSeverityRank ?? 5,
    kevOnly: rule?.kevOnly ?? false,
    hostScope: rule?.hostIds ? "selected" : "all",
    hostIds: rule?.hostIds ?? [],
    channelIds: rule?.channels.map((c) => c.id) ?? (channels.length === 1 ? [channels[0].id] : []),
    dedupWindowSeconds: rule?.dedupWindowSeconds ?? 3600,
    digest: rule?.digest ?? false,
    digestIntervalSeconds: rule?.digestIntervalSeconds ?? 3600,
  });
  // Archived hosts never alert: offer only the ones this rule already
  // scopes, so they can be removed.
  const scopeHosts = hosts.filter((h) => !h.archived || rule?.hostIds?.includes(h.id));
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const set = <K extends keyof RuleInput>(k: K, val: RuleInput[K]) =>
    setV((prev) => ({ ...prev, [k]: val }));
  const hasFindingEvents = v.eventTypes.some(isFindingEvent);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      const res = rule ? await updateRule(rule.id, v) : await createRule(v);
      if (!res.ok) {
        setError(res.error);
        setErrors(res.fieldErrors ?? {});
        return;
      }
      onOpenChange(false);
    });
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{rule ? `Edit ${rule.name}` : "New alert rule"}</DialogTitle>
          <DialogDescription>
            Which events to send, filtered by severity, KEV and hosts, to which channels.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-4">
          {error && (
            <Alert variant="destructive">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="rule-name">Name</Label>
            <Input
              id="rule-name"
              value={v.name}
              maxLength={100}
              placeholder="e.g. Critical and KEV findings"
              onChange={(e) => set("name", e.target.value)}
            />
            <Err msg={errors.name} />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>Events</Label>
            <CheckList
              items={EVENT_TYPES}
              selected={v.eventTypes}
              onToggle={(t) => set("eventTypes", toggle(v.eventTypes, t))}
              id={(t) => t}
              label={(t) => eventTypeLabel(t)}
            />
            <Err msg={errors.eventTypes} />
          </div>

          {hasFindingEvents && (
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="rule-severity">Minimum severity</Label>
                <Select
                  value={String(v.minSeverityRank)}
                  onValueChange={(s) => set("minSeverityRank", Number(s))}
                >
                  <SelectTrigger id="rule-severity" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_FLOORS.map((s) => (
                      <SelectItem key={s.rank} value={String(s.rank)}>
                        {s.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <label className="flex items-center gap-2 self-end pb-2 text-sm">
                <input
                  type="checkbox"
                  className="accent-primary size-4"
                  checked={v.kevOnly}
                  onChange={(e) => set("kevOnly", e.target.checked)}
                />
                Known exploited (KEV) only
              </label>
              <p className="text-muted-foreground text-xs sm:col-span-2">
                Severity and KEV filters apply to finding events only.
              </p>
            </div>
          )}

          <div className="flex flex-col gap-1.5">
            <Label>Hosts</Label>
            <div className="flex gap-4 text-sm">
              {(["all", "selected"] as const).map((s) => (
                <label key={s} className="flex items-center gap-2">
                  <input
                    type="radio"
                    name="host-scope"
                    className="accent-primary size-4"
                    checked={v.hostScope === s}
                    onChange={() => set("hostScope", s)}
                  />
                  {s === "all" ? "All hosts (including future ones)" : "Selected hosts"}
                </label>
              ))}
            </div>
            {v.hostScope === "selected" &&
              (scopeHosts.length === 0 ? (
                <p className="text-muted-foreground text-sm">No hosts yet.</p>
              ) : (
                <CheckList
                  items={scopeHosts}
                  selected={v.hostIds}
                  onToggle={(h) => set("hostIds", toggle(v.hostIds, h))}
                  id={(h) => h.id}
                  label={(h) => (
                    <span>
                      {h.hostname}
                      {h.label && <span className="text-muted-foreground"> {h.label}</span>}
                      {h.archived && <span className="text-muted-foreground"> (archived)</span>}
                    </span>
                  )}
                />
              ))}
            <Err msg={errors.hostIds} />
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>Send to</Label>
            {channels.length === 0 ? (
              <p className="text-muted-foreground text-sm">
                No channels yet: add one on the Channels tab first.
              </p>
            ) : (
              <CheckList
                items={channels}
                selected={v.channelIds}
                onToggle={(c) => set("channelIds", toggle(v.channelIds, c))}
                id={(c) => c.id}
                label={(c) => (
                  <span>
                    {c.name}{" "}
                    <span className="text-muted-foreground">
                      ({channelType(c.type)?.label ?? c.type}
                      {!c.enabled && ", disabled"})
                    </span>
                  </span>
                )}
              />
            )}
            <Err msg={errors.channelIds} />
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="rule-delivery">Delivery</Label>
              <Select
                value={v.digest ? "digest" : "immediate"}
                onValueChange={(s) => set("digest", s === "digest")}
              >
                <SelectTrigger id="rule-delivery" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="immediate">Immediately</SelectItem>
                  <SelectItem value="digest">Digest</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {v.digest && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="rule-interval">At most every</Label>
                <Select
                  value={String(v.digestIntervalSeconds)}
                  onValueChange={(s) => set("digestIntervalSeconds", Number(s))}
                >
                  <SelectTrigger id="rule-interval" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {DIGEST_INTERVALS.map((s) => (
                      <SelectItem key={s} value={String(s)}>
                        {durationLabel(s)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="rule-dedup">Don&apos;t repeat within</Label>
              <Select
                value={String(v.dedupWindowSeconds)}
                onValueChange={(s) => set("dedupWindowSeconds", Number(s))}
              >
                <SelectTrigger id="rule-dedup" className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {DEDUP_WINDOWS.map((s) => (
                    <SelectItem key={s} value={String(s)}>
                      {durationLabel(s)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <p className="text-muted-foreground text-xs sm:col-span-2">
              The same event about the same finding or agent is sent once per window (e.g. a finding
              that flaps open and resolved).
            </p>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={pending}>
              {pending && <Loader2 className="animate-spin" />}
              {rule ? "Save" : "Create rule"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
