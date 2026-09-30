"use client";

import { FieldError } from "@/components/notifications/shared";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { Role } from "@/lib/roles";

import { TemporaryPasswordField } from "./password-field";
import { RolePicker } from "./role-picker";

export type NewMemberForm = {
  username: string;
  email: string;
  name: string;
  role: Role;
  password: string;
};

const TEXT_FIELDS = [
  {
    key: "username",
    label: "Username",
    hint: "Used to sign in. Letters, numbers, underscores and dots.",
    required: true,
  },
  { key: "email", label: "Email", hint: null, required: true },
  {
    key: "name",
    label: "Full name (optional)",
    hint: "Shown instead of the username where there's room.",
    required: false,
  },
] as const;

// Input ids are member-<field>, so a failed submit can focus the first
// invalid one.
export const fieldInputId = (key: string) => `member-${key}`;

// The Add member form's fields. Errors show on the field they're about.
export function AddMemberFields({
  form,
  errors,
  onChange,
  autoFocus,
}: {
  form: NewMemberForm;
  errors: Record<string, string>;
  onChange: <K extends keyof NewMemberForm>(key: K, value: NewMemberForm[K]) => void;
  autoFocus?: boolean;
}) {
  return (
    <>
      {TEXT_FIELDS.map((f, i) => {
        const id = fieldInputId(f.key);
        const error = errors[f.key];
        const describedBy = [f.hint && `${id}-hint`, error && `${id}-error`]
          .filter(Boolean)
          .join(" ");
        return (
          <div key={f.key} className="flex flex-col gap-1.5">
            <Label htmlFor={id}>{f.label}</Label>
            <Input
              id={id}
              type={f.key === "email" ? "email" : "text"}
              value={form[f.key]}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              required={f.required}
              autoFocus={autoFocus && i === 0}
              aria-invalid={error ? true : undefined}
              aria-describedby={describedBy || undefined}
              onChange={(e) => onChange(f.key, e.target.value)}
            />
            {f.hint && (
              <p id={`${id}-hint`} className="text-muted-foreground text-xs">
                {f.hint}
              </p>
            )}
            <FieldError id={`${id}-error`} msg={error} />
          </div>
        );
      })}
      <div className="flex flex-col gap-1.5">
        <RolePicker
          id={fieldInputId("role")}
          value={form.role}
          onChange={(r) => onChange("role", r)}
        />
        <FieldError msg={errors.role} />
      </div>
      <TemporaryPasswordField
        id={fieldInputId("password")}
        value={form.password}
        onChange={(v) => onChange("password", v)}
        error={errors.password}
      />
    </>
  );
}
