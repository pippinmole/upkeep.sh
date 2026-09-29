"use client";

import { Check, Copy } from "lucide-react";
import { useState } from "react";

import { Button, type ButtonProps } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

interface Props extends ButtonProps {
  text: string;
  className?: string;
}

export function CopyButton({ text, className, ...rest }: Props) {
  const [isCopied, setIsCopied] = useState(false);

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setIsCopied(true);
      setTimeout(() => setIsCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy text: ", err);
    }
  };

  return (
    <TooltipProvider>
      <Tooltip delayDuration={0}>
        <TooltipTrigger asChild>
          <Button
            type="button"
            variant="outline"
            size="icon"
            className={className}
            onClick={copyToClipboard}
            aria-label={isCopied ? "Copied" : "Copy to clipboard"}
            {...rest}
          >
            {isCopied ? (
              <Check strokeWidth={1.5} className="text-success m-auto" />
            ) : (
              <Copy strokeWidth={1.5} className="m-auto" />
            )}
          </Button>
        </TooltipTrigger>
        <TooltipContent>
          <p>{isCopied ? "Copied!" : "Copy"}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
