"use client";

import { AlertTriangle } from "lucide-react";

import { CopyButton } from "@/components/copy-button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { channelType } from "@/lib/notifiers";

// A generated secret, displayed exactly once (after create or rotate). A
// warning, not an error: nothing went wrong.
export function SecretOnce({ type, secrets }: { type: string; secrets: Record<string, string> }) {
  const spec = channelType(type);
  return (
    <div className="flex flex-col gap-4">
      <Alert className="border-warning/40 bg-warning/10 text-warning-fg [&>svg]:text-warning-fg">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Copy this now</AlertTitle>
        <AlertDescription>
          This secret is shown only once and can&apos;t be retrieved again. If you lose it, rotate
          it from the channel&apos;s edit dialog.
        </AlertDescription>
      </Alert>
      {Object.entries(secrets).map(([key, value]) => {
        const field = spec?.fields.find((f) => f.key === key);
        return (
          <div key={key} className="flex flex-col gap-1.5">
            <Label htmlFor={`secret-${key}`}>{field?.label ?? key}</Label>
            <div className="relative">
              <Input
                id={`secret-${key}`}
                readOnly
                value={value}
                className="pr-12 font-mono text-xs"
              />
              <CopyButton
                className="absolute top-1/2 right-1 h-7 w-7 -translate-y-1/2"
                text={value}
              />
            </div>
            {field?.help && <p className="text-muted-foreground text-xs">{field.help}</p>}
          </div>
        );
      })}
    </div>
  );
}
