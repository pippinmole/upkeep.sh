"use client";

import { ChevronDown } from "lucide-react";
import { useState } from "react";

import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { sentenceCase, splitFirstSentence } from "@/lib/collector-message";
import { cn } from "@/lib/utils";

import { InlineCodeText } from "./inline-code-text";

// Messages up to this length are shown whole; longer ones show their first
// sentence with the rest behind a toggle.
const COLLAPSE_OVER = 160;

export function CollectorFailureMessage({ error }: { error: string }) {
  const [open, setOpen] = useState(false);
  const msg = sentenceCase(error.trim());
  const { summary, rest } = splitFirstSentence(msg);

  if (msg.length <= COLLAPSE_OVER || !rest) {
    return (
      <p className="text-muted-foreground leading-relaxed">
        <InlineCodeText text={msg} />
      </p>
    );
  }

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="flex flex-col gap-1.5">
      <p className="text-muted-foreground leading-relaxed">
        <InlineCodeText text={summary} />
      </p>
      <CollapsibleContent>
        <p className="text-muted-foreground leading-relaxed">
          <InlineCodeText text={rest} />
        </p>
      </CollapsibleContent>
      <CollapsibleTrigger className="text-foreground focus-visible:ring-ring inline-flex w-fit items-center gap-1 rounded-sm text-xs font-medium hover:underline focus-visible:ring-1 focus-visible:outline-hidden">
        {open ? "Show less" : "Show details"}
        <ChevronDown
          aria-hidden
          className={cn("size-3.5 transition-transform", open && "rotate-180")}
        />
      </CollapsibleTrigger>
    </Collapsible>
  );
}
