"use client";

import { AlertTriangle, Loader2 } from "lucide-react";
import { useState, useTransition } from "react";

import { NotificationSettingsLink } from "@/components/notifications/links";
import { ChannelCheckList, FieldError as Err, toggle } from "@/components/notifications/shared";
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
import { type Condition, validateCondition } from "@/lib/alert-conditions";
import { DIGEST_INTERVALS, durationLabel } from "@/lib/notifiers";
import type { AlertRuleRow } from "@/lib/queries-alerts";
import type { ChannelRow, ScopeHost } from "@/lib/queries-notifications";

import { createAlertRule, updateAlertRule } from "@/app/dashboard/alert-rule-actions";

import {
  conditionFromDraft,
  type ConditionDraft,
  draftForProperty,
  draftFromCondition,
} from "./condition-draft";
import { ConditionFields } from "./condition-fields";
import { ScopeFields } from "./scope-fields";

export function RuleDialog({
  open,
  onOpenChange,
  rule,
  channels,
  hosts,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  rule?: AlertRuleRow;
  channels: ChannelRow[];
  hosts: ScopeHost[];
}) {
  const [name, setName] = useState(rule?.name ?? "");
  const [draft, setDraft] = useState<ConditionDraft>(
    rule ? draftFromCondition(rule.condition) : draftForProperty("listening_port"),
  );
  const [scope, setScope] = useState<"all" | "selected">(rule?.hostIds ? "selected" : "all");
  const [hostIds, setHostIds] = useState<string[]>(rule?.hostIds ?? []);
  const [channelIds, setChannelIds] = useState<string[]>(
    rule?.channels.map((c) => c.id) ?? (channels.length === 1 ? [channels[0].id] : []),
  );
  const [notifyOnResolve, setNotifyOnResolve] = useState(rule?.notifyOnResolve ?? true);
  const [digest, setDigest] = useState(rule?.digest ?? false);
  const [digestInterval, setDigestInterval] = useState(rule?.digestIntervalSeconds ?? 3600);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  // Archived hosts never alert: offer only the ones this rule already
  // scopes, so they can be removed.
  const scopeHosts = hosts.filter((h) => !h.archived || rule?.hostIds?.includes(h.id));

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    // Instant feedback; the action validates again.
    const checked = validateCondition(conditionFromDraft(draft));
    if (!checked.ok) {
      setErrors({ [`condition.${checked.field}`]: checked.message });
      return;
    }
    const input = {
      name,
      condition: checked.condition as Condition,
      hostScope: scope,
      hostIds,
      channelIds,
      notifyOnResolve,
      digest,
      digestIntervalSeconds: digestInterval,
    };
    startTransition(async () => {
      const res = rule ? await updateAlertRule(rule.id, input) : await createAlertRule(input);
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
            A condition on your hosts&apos; state. It fires once when a host starts matching and
            resolves when it stops, never once per snapshot.
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
              value={name}
              maxLength={100}
              placeholder="e.g. RDP exposed"
              onChange={(e) => setName(e.target.value)}
            />
            <Err msg={errors.name} />
          </div>

          <ConditionFields draft={draft} onChange={setDraft} errors={errors} />

          <ScopeFields
            scope={scope}
            hostIds={hostIds}
            hosts={scopeHosts}
            onScope={setScope}
            onHosts={setHostIds}
            error={errors.hostIds}
          />

          <div className="flex flex-col gap-1.5">
            <Label>Send to</Label>
            {channels.length === 0 ? (
              <p className="text-muted-foreground text-sm">
                No channels yet: alerts show in the dashboard only. Add one in{" "}
                <NotificationSettingsLink /> to be notified.
              </p>
            ) : (
              <ChannelCheckList
                channels={channels}
                selected={channelIds}
                onToggle={(c) => setChannelIds(toggle(channelIds, c))}
              />
            )}
            <Err msg={errors.channelIds} />
            {channels.length > 0 && (
              <p className="text-muted-foreground text-xs">
                None ticked: the rule only shows alerts in the dashboard.
              </p>
            )}
          </div>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="accent-primary size-4"
              checked={notifyOnResolve}
              onChange={(e) => setNotifyOnResolve(e.target.checked)}
            />
            Also notify when an alert resolves
          </label>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="rule-delivery">Delivery</Label>
              <Select
                value={digest ? "digest" : "immediate"}
                onValueChange={(s) => setDigest(s === "digest")}
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
            {digest && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="rule-interval">At most every</Label>
                <Select
                  value={String(digestInterval)}
                  onValueChange={(s) => setDigestInterval(Number(s))}
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
                <Err msg={errors.digestIntervalSeconds} />
              </div>
            )}
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
