"use client";

import { AlertTriangle, Check, Copy } from "lucide-react";
import { useState } from "react";

import { CopyButton } from "@/components/copy-button";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

import { signInDetailsText } from "./validation";

// The success step of Add member and Reset password: everything the admin
// has to pass on, shown once (the password isn't stored in clear text).
export function SignInDetails({
  username,
  password,
  reset,
}: {
  username: string;
  password: string;
  reset?: boolean;
}) {
  // Derived on the client: the page the admin is on is the install's URL.
  // Only ever rendered after a submit, so there's no server render to match.
  const loginUrl = typeof window === "undefined" ? "/login" : `${window.location.origin}/login`;
  const [copied, setCopied] = useState(false);

  async function copyAll() {
    try {
      await navigator.clipboard.writeText(
        signInDetailsText({ loginUrl, username, password, reset }),
      );
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy sign-in details: ", err);
    }
  }

  const fields = [
    { key: "url", label: "Sign-in page", value: loginUrl },
    { key: "username", label: "Username", value: username },
    { key: "password", label: "Temporary password", value: password },
  ];

  return (
    <div className="flex flex-col gap-4">
      <Alert className="border-warning/40 bg-warning/10 text-warning-fg [&>svg]:text-warning-fg">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Copy these sign-in details now</AlertTitle>
        <AlertDescription>
          The temporary password isn&rsquo;t shown again. If it&rsquo;s lost, reset it from the
          member&rsquo;s menu.
        </AlertDescription>
      </Alert>
      {fields.map((f) => (
        <div key={f.key} className="flex flex-col gap-1.5">
          <Label htmlFor={`sign-in-${f.key}`}>{f.label}</Label>
          <div className="relative">
            <Input
              id={`sign-in-${f.key}`}
              readOnly
              value={f.value}
              className="pr-10 font-mono text-xs"
              onFocus={(e) => e.currentTarget.select()}
            />
            <CopyButton
              variant="ghost"
              className="absolute top-1/2 right-1 size-7 -translate-y-1/2"
              text={f.value}
            />
          </div>
        </div>
      ))}
      <Button type="button" variant="outline" className="self-start" onClick={copyAll} autoFocus>
        {copied ? <Check className="text-success" /> : <Copy />}
        {copied ? "Copied" : "Copy sign-in details"}
      </Button>
    </div>
  );
}
