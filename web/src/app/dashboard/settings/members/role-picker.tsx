"use client";

import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { ROLE_DESCRIPTIONS, ROLE_LABELS, type Role } from "@/lib/roles";

// Least privileged (and the default) first.
const ORDER: Role[] = ["member", "admin"];

// The two roles as selectable cards, each with what it allows.
export function RolePicker({
  id,
  value,
  onChange,
}: {
  id: string;
  value: Role;
  onChange: (r: Role) => void;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <span id={`${id}-label`} className="text-sm leading-none font-medium">
        Role
      </span>
      <RadioGroup
        id={id}
        value={value}
        onValueChange={(v) => onChange(v as Role)}
        aria-labelledby={`${id}-label`}
        className="grid-cols-1 gap-2 sm:grid-cols-2"
      >
        {ORDER.map((r) => (
          <label
            key={r}
            htmlFor={`${id}-${r}`}
            className="has-[[data-state=checked]]:border-primary has-[[data-state=checked]]:bg-muted/50 hover:bg-muted/30 flex cursor-pointer items-start gap-3 rounded-md border p-3 transition-colors"
          >
            <RadioGroupItem id={`${id}-${r}`} value={r} className="mt-0.5" />
            <span className="flex flex-col gap-0.5">
              <span className="text-sm font-medium">{ROLE_LABELS[r]}</span>
              <span className="text-muted-foreground text-xs">{ROLE_DESCRIPTIONS[r]}</span>
            </span>
          </label>
        ))}
      </RadioGroup>
    </div>
  );
}
