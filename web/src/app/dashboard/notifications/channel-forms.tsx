"use client";

import { KeyRound, RotateCw } from "lucide-react";
import type { ComponentType } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { ChannelField, ChannelType } from "@/lib/notifiers";

export type ChannelFieldsProps = {
  spec: ChannelType;
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
  errors: Record<string, string>;
  mode: "create" | "edit";
  // Secret keys already stored (edit mode).
  secretKeys: string[];
  // Rotate a generated secret (edit mode).
  onRotate?: (key: string) => void;
  rotating?: boolean;
};

// Per-type form overrides, registered here and only here. A channel type
// whose form can't be expressed by its declared fields (e.g. an OAuth
// "connect" button) gets a component; every other type — webhook today —
// is rendered from its schema by SchemaFields.
const CUSTOM_FORMS: Partial<Record<string, ComponentType<ChannelFieldsProps>>> = {};

export function ChannelFields(props: ChannelFieldsProps) {
  const Form = CUSTOM_FORMS[props.spec.type] ?? SchemaFields;
  return <Form {...props} />;
}

function FieldError({ msg }: { msg?: string }) {
  return msg ? <p className="text-destructive text-xs">{msg}</p> : null;
}

function Help({ field }: { field: ChannelField }) {
  return field.help ? <p className="text-muted-foreground text-xs">{field.help}</p> : null;
}

// Renders any channel type from its declared fields.
export function SchemaFields({
  spec,
  values,
  onChange,
  errors,
  mode,
  secretKeys,
  onRotate,
  rotating,
}: ChannelFieldsProps) {
  return (
    <>
      {spec.fields.map((f) => {
        const id = `channel-${f.key}`;
        const isSet = secretKeys.includes(f.key);

        if (f.generated) {
          return (
            <div key={f.key} className="flex flex-col gap-1.5">
              <Label>{f.label}</Label>
              <div className="bg-muted/50 flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
                <KeyRound className="text-muted-foreground size-4 shrink-0" />
                <span className="flex-1">
                  {mode === "create"
                    ? "Generated when you save, and shown once."
                    : isSet
                      ? "Set. It can't be shown again; rotate it to get a new one."
                      : "Not set."}
                </span>
                {mode === "edit" && onRotate && (
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={rotating}
                    onClick={() => onRotate(f.key)}
                  >
                    <RotateCw className={rotating ? "animate-spin" : undefined} />
                    Rotate
                  </Button>
                )}
              </div>
              <Help field={f} />
            </div>
          );
        }

        if (f.type === "bool") {
          return (
            <div key={f.key} className="flex flex-col gap-1.5">
              <label className="flex items-center gap-2 text-sm">
                <input
                  id={id}
                  type="checkbox"
                  className="accent-primary size-4"
                  checked={values[f.key] === "true"}
                  onChange={(e) => onChange(f.key, e.target.checked ? "true" : "false")}
                />
                {f.label}
              </label>
              <Help field={f} />
              <FieldError msg={errors[f.key]} />
            </div>
          );
        }

        if (f.type === "select") {
          return (
            <div key={f.key} className="flex flex-col gap-1.5">
              <Label htmlFor={id}>{f.label}</Label>
              <Select value={values[f.key] ?? ""} onValueChange={(v) => onChange(f.key, v)}>
                <SelectTrigger id={id} className="w-full">
                  <SelectValue placeholder={f.placeholder ?? "Choose…"} />
                </SelectTrigger>
                <SelectContent>
                  {f.options?.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Help field={f} />
              <FieldError msg={errors[f.key]} />
            </div>
          );
        }

        const inputType =
          f.type === "secret" ? "password" : f.type === "email" ? "email" : f.type === "url" ? "url" : "text";
        return (
          <div key={f.key} className="flex flex-col gap-1.5">
            <Label htmlFor={id}>
              {f.label}
              {f.required && !(f.secret && isSet) && <span className="text-destructive">*</span>}
            </Label>
            <Input
              id={id}
              type={inputType}
              value={values[f.key] ?? ""}
              maxLength={f.maxLength}
              autoComplete={f.secret ? "new-password" : "off"}
              placeholder={
                f.secret && isSet ? "Leave blank to keep the current value" : f.placeholder
              }
              aria-invalid={!!errors[f.key]}
              onChange={(e) => onChange(f.key, e.target.value)}
            />
            <Help field={f} />
            <FieldError msg={errors[f.key]} />
          </div>
        );
      })}
    </>
  );
}
