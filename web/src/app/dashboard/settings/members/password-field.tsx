"use client";

import { Wand2 } from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { FieldError } from "@/components/notifications/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { generateTemporaryPassword, MIN_PASSWORD } from "./validation";

// A temporary password: typed, or generated. Shown in clear text so the
// admin can pass it on; the user must replace it at first sign-in.
export function TemporaryPasswordField({
  id,
  value,
  onChange,
  error,
}: {
  id: string;
  value: string;
  onChange: (v: string) => void;
  error?: string;
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>Temporary password</Label>
      <div className="flex gap-2">
        <Input
          id={id}
          value={value}
          autoComplete="off"
          spellCheck={false}
          className="font-mono"
          minLength={MIN_PASSWORD}
          aria-invalid={error ? true : undefined}
          onChange={(e) => onChange(e.target.value)}
        />
        <Button
          type="button"
          variant="outline"
          onClick={() => onChange(generateTemporaryPassword())}
        >
          <Wand2 />
          Generate
        </Button>
        {value && <CopyButton text={value} variant="outline" />}
      </div>
      <p className="text-muted-foreground text-xs">
        At least {MIN_PASSWORD} characters. They&rsquo;ll be asked to choose their own when they
        sign in.
      </p>
      <FieldError msg={error} />
    </div>
  );
}
