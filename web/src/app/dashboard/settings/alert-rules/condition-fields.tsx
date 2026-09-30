"use client";

import { FieldError as Err } from "@/components/notifications/shared";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { type Operator, PROPERTIES, propertyByKey } from "@/lib/alert-conditions";

import { type ConditionDraft, draftForProperty } from "./condition-draft";

// Property -> operator -> value -> options, all rendered from the Go
// catalogue (lib/alert-properties.json). A new property needs no change
// here. errors are keyed like the action's: "condition.value",
// "condition.options.bind", ...
export function ConditionFields({
  draft,
  onChange,
  errors,
}: {
  draft: ConditionDraft;
  onChange: (d: ConditionDraft) => void;
  errors: Record<string, string>;
}) {
  const property = propertyByKey(draft.property);
  const operator = property?.operators.find((o) => o.key === draft.operator);

  return (
    <div className="flex flex-col gap-3 rounded-md border p-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="cond-property">When</Label>
          <Select value={draft.property} onValueChange={(k) => onChange(draftForProperty(k))}>
            <SelectTrigger id="cond-property" className="w-full">
              <SelectValue placeholder="Choose a property" />
            </SelectTrigger>
            <SelectContent>
              {PROPERTIES.map((p) => (
                <SelectItem key={p.key} value={p.key}>
                  {p.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Err msg={errors["condition.property"]} />
        </div>
        {property && property.operators.length > 1 && (
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="cond-operator">Condition</Label>
            {/* Keyed: Radix Select keeps showing the old item text when its
                items change under a controlled value. */}
            <Select
              key={draft.property}
              value={draft.operator}
              onValueChange={(k) => {
                const next = property.operators.find((o) => o.key === k);
                const keepValue = next?.value.kind === operator?.value.kind;
                onChange({
                  ...draft,
                  operator: k,
                  valueText: keepValue
                    ? draft.valueText
                    : next?.value.kind === "enum"
                      ? (next.value.choices?.[0]?.value ?? "")
                      : "",
                });
              }}
            >
              <SelectTrigger id="cond-operator" className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {property.operators.map((o) => (
                  <SelectItem key={o.key} value={o.key}>
                    {o.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Err msg={errors["condition.operator"]} />
          </div>
        )}
      </div>
      {property && <p className="text-muted-foreground text-xs">{property.description}</p>}

      {operator && operator.value.kind !== "none" && (
        <ValueField
          key={`${draft.property}.${draft.operator}`}
          operator={operator}
          text={draft.valueText}
          onChange={(valueText) => onChange({ ...draft, valueText })}
          error={errors["condition.value"]}
        />
      )}

      {property?.options && property.options.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2">
          {property.options.map((o) => (
            <div key={o.key} className="flex flex-col gap-1.5">
              <Label htmlFor={`cond-opt-${o.key}`}>{o.label}</Label>
              <Select
                key={`${draft.property}.${o.key}`}
                value={draft.options[o.key] ?? o.default}
                onValueChange={(v) =>
                  onChange({ ...draft, options: { ...draft.options, [o.key]: v } })
                }
              >
                <SelectTrigger id={`cond-opt-${o.key}`} className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {o.choices.map((c) => (
                    <SelectItem key={c.value} value={c.value}>
                      {c.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {o.help && <p className="text-muted-foreground text-xs">{o.help}</p>}
              <Err msg={errors[`condition.options.${o.key}`]} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function ValueField({
  operator,
  text,
  onChange,
  error,
}: {
  operator: Operator;
  text: string;
  onChange: (t: string) => void;
  error?: string;
}) {
  const v = operator.value;
  const hint =
    v.kind === "int_list"
      ? `Separate with commas (up to ${v.maxItems}).`
      : v.kind === "string_list"
        ? `Separate with commas (up to ${v.maxItems}).`
        : v.kind === "int"
          ? `${v.min} to ${v.max}${v.unit ? ` ${v.unit}` : ""}.`
          : "";
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor="cond-value">{v.label ?? "Value"}</Label>
      {v.kind === "enum" ? (
        <Select key={operator.key} value={text} onValueChange={onChange}>
          <SelectTrigger id="cond-value" className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {v.choices?.map((c) => (
              <SelectItem key={c.value} value={c.value}>
                {c.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      ) : (
        <Input
          id="cond-value"
          value={text}
          inputMode={v.kind === "int" || v.kind === "int_list" ? "numeric" : undefined}
          placeholder={v.placeholder}
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {(v.help || hint) && (
        <p className="text-muted-foreground text-xs">{[v.help, hint].filter(Boolean).join(" ")}</p>
      )}
      <Err msg={error} />
    </div>
  );
}
