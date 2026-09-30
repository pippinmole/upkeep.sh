"use client";

import { RefreshCw } from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { FieldError } from "@/components/notifications/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { generateTemporaryPassword, MIN_PASSWORD } from "./validation";

// A temporary password: typed, or generated. Shown in clear text so the
// admin can pass it on; the user must replace it at first sign-in. The
// generate and copy buttons sit inside the input so it keeps its width.
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
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  return (
    <div className="flex flex-col gap-1.5">
      <Label htmlFor={id}>Temporary password</Label>
      <div className="relative">
        <Input
          id={id}
          value={value}
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          className="pr-16 font-mono"
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${hintId} ${errorId}` : hintId}
          onChange={(e) => onChange(e.target.value)}
        />
        <div className="absolute top-1/2 right-1 flex -translate-y-1/2 gap-0.5 [&>button]:size-7">
          <Button
            type="button"
            variant="ghost"
            size="icon"
            aria-label="Generate a new password"
            title="Generate a new password"
            onClick={() => onChange(generateTemporaryPassword())}
          >
            <RefreshCw />
          </Button>
          <CopyButton variant="ghost" text={value} disabled={!value} />
        </div>
      </div>
      <p id={hintId} className="text-muted-foreground text-xs">
        At least {MIN_PASSWORD} characters. They&rsquo;ll choose their own when they sign in.
      </p>
      <FieldError id={errorId} msg={error} />
    </div>
  );
}
