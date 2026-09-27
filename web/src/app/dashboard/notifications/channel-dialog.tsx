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
import { CHANNEL_TYPES, channelType } from "@/lib/notifiers";
import type { ChannelRow } from "@/lib/queries-notifications";

import { createChannel, rotateChannelSecret, updateChannel } from "./actions";
import { ChannelFields } from "./channel-forms";
import { SecretOnce } from "./secret-once";

// Create (channel = undefined) or edit a channel. The form body is the
// channel type's generic, schema-driven form (channel-forms.tsx).
export function ChannelDialog({
  open,
  onOpenChange,
  channel,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  channel?: ChannelRow;
}) {
  const mode = channel ? "edit" : "create";
  const [type, setType] = useState(channel?.type ?? CHANNEL_TYPES[0]?.type ?? "");
  const [name, setName] = useState(channel?.name ?? "");
  const [values, setValues] = useState<Record<string, string>>({ ...channel?.config });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [shown, setShown] = useState<Record<string, string> | null>(null);
  const [pending, startTransition] = useTransition();
  const [rotating, startRotate] = useTransition();
  const spec = channelType(type);

  function close(next: boolean) {
    onOpenChange(next);
    if (!next) {
      // Never keep a shown secret around for the next open.
      setShown(null);
      setErrors({});
      setError(null);
      if (!channel) {
        setName("");
        setValues({});
      }
    }
  }

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    startTransition(async () => {
      let generated: Record<string, string> = {};
      if (channel) {
        const res = await updateChannel(channel.id, { name, values });
        if (!res.ok) {
          setError(res.error);
          setErrors(res.fieldErrors ?? {});
          return;
        }
      } else {
        const res = await createChannel({ name, type, values });
        if (!res.ok) {
          setError(res.error);
          setErrors(res.fieldErrors ?? {});
          return;
        }
        generated = res.generated;
      }
      setErrors({});
      if (Object.keys(generated).length > 0) setShown(generated);
      else close(false);
    });
  }

  function rotate(key: string) {
    if (!channel) return;
    startRotate(async () => {
      const res = await rotateChannelSecret(channel.id, key);
      if (res.ok) setShown({ [key]: res.secret });
      else setError(res.error);
    });
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {shown ? "Channel secret" : mode === "create" ? "Add channel" : `Edit ${channel?.name}`}
          </DialogTitle>
          <DialogDescription>{spec?.description}</DialogDescription>
        </DialogHeader>

        {shown ? (
          <>
            <SecretOnce type={type} secrets={shown} />
            <DialogFooter>
              <Button onClick={() => close(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form onSubmit={submit} className="flex flex-col gap-4">
            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            {mode === "create" && CHANNEL_TYPES.length > 1 && (
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="channel-type">Type</Label>
                <Select
                  value={type}
                  onValueChange={(t) => {
                    setType(t);
                    setValues({});
                    setErrors({});
                  }}
                >
                  <SelectTrigger id="channel-type" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {CHANNEL_TYPES.map((t) => (
                      <SelectItem key={t.type} value={t.type}>
                        {t.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="channel-name">
                Name<span className="text-destructive">*</span>
              </Label>
              <Input
                id="channel-name"
                value={name}
                maxLength={100}
                placeholder="e.g. Ops webhook"
                aria-invalid={!!errors.name}
                onChange={(e) => setName(e.target.value)}
              />
              {errors.name && <p className="text-destructive text-xs">{errors.name}</p>}
            </div>
            {spec ? (
              <ChannelFields
                spec={spec}
                values={values}
                onChange={(k, v) => setValues((prev) => ({ ...prev, [k]: v }))}
                errors={errors}
                mode={mode}
                secretKeys={channel?.secretKeys ?? []}
                onRotate={rotate}
                rotating={rotating}
              />
            ) : (
              <p className="text-muted-foreground text-sm">
                This channel type ({type}) is not supported by this version.
              </p>
            )}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={pending || !spec}>
                {pending && <Loader2 className="animate-spin" />}
                {mode === "create" ? "Add channel" : "Save"}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
