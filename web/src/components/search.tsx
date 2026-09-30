"use client";

import { Search as SearchIcon } from "lucide-react";
import { useSyncExternalStore } from "react";

import { cn } from "@/lib/utils";

import { useSearch } from "./search-provider";
import { Button } from "./ui/button";

const noSubscribe = () => () => {};

function isApplePlatform(): boolean {
  const nav = navigator as Navigator & { userAgentData?: { platform?: string } };
  return /mac|iphone|ipad|ipod/i.test(nav.userAgentData?.platform || nav.platform || "");
}

// The modifier for keyboard shortcuts: "⌘" on Apple platforms, else
// "Ctrl". Renders "Ctrl" on the server and during hydration, then the
// platform's own, so the markup matches.
export function useModKey(): "⌘" | "Ctrl" {
  const apple = useSyncExternalStore(noSubscribe, isApplePlatform, () => false);
  return apple ? "⌘" : "Ctrl";
}

// A shortcut in a <kbd>: "Ctrl K" or "⌘K".
export function Shortcut({ keyName, className }: { keyName: string; className?: string }) {
  const mod = useModKey();
  return (
    <kbd
      className={cn(
        "bg-muted text-muted-foreground pointer-events-none inline-flex h-5 items-center gap-1 rounded border px-1.5 font-mono text-[10px] font-medium select-none",
        className,
      )}
    >
      {mod === "⌘" ? `⌘${keyName}` : `Ctrl ${keyName}`}
    </kbd>
  );
}

interface Props {
  className?: string;
  placeholder?: string;
}

// Full search field on sm and up, an icon button below.
export function Search({ className = "", placeholder = "Search CVEs, hosts, packages…" }: Props) {
  const { setOpen } = useSearch();
  return (
    <>
      <Button
        variant="outline"
        className={cn(
          "bg-muted/25 text-muted-foreground hover:bg-muted/50 relative hidden h-8 w-full justify-start rounded-md text-sm font-normal shadow-none sm:flex sm:pr-14 md:w-40 lg:w-56 xl:w-64",
          className,
        )}
        onClick={() => setOpen(true)}
      >
        <SearchIcon
          aria-hidden="true"
          className="absolute top-1/2 left-1.5 size-4 -translate-y-1/2"
        />
        <span className="ml-3 truncate">{placeholder}</span>
        <Shortcut keyName="K" className="absolute top-[0.3rem] right-[0.3rem]" />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Search"
        className="size-8 sm:hidden"
        onClick={() => setOpen(true)}
      >
        <SearchIcon aria-hidden="true" className="size-4" />
      </Button>
    </>
  );
}
