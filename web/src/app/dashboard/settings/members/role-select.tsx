"use client";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ROLE_DESCRIPTIONS, ROLE_LABELS, ROLES, type Role } from "@/lib/roles";

export function RoleSelect({
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
      <Select value={value} onValueChange={(v) => onChange(v as Role)}>
        <SelectTrigger id={id} className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {ROLES.map((r) => (
            <SelectItem key={r} value={r}>
              {ROLE_LABELS[r]}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-muted-foreground text-xs">{ROLE_DESCRIPTIONS[value]}</p>
    </div>
  );
}
