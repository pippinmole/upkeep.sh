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

// The top bar's search trigger, styled for the dark bar: a field from xl
// up, an icon button below (narrower bars need the room for the tabs).
export function Search({ className = "", placeholder = "Search CVEs, hosts, packages…" }: Props) {
  const { setOpen } = useSearch();
  return (
    <>
      <Button
        variant="ghost"
        className={cn(
          "border-topbar-foreground/15 bg-topbar-foreground/5 text-topbar-muted hover:bg-topbar-foreground/10 hover:text-topbar-foreground relative hidden h-8 w-64 justify-start rounded-md border pr-14 text-sm font-normal xl:flex",
          className,
        )}
        onClick={() => setOpen(true)}
      >
        <SearchIcon
          aria-hidden="true"
          className="absolute top-1/2 left-1.5 size-4 -translate-y-1/2"
        />
        <span className="ml-3 truncate">{placeholder}</span>
        <Shortcut
          keyName="K"
          className="border-topbar-foreground/15 bg-topbar-foreground/10 text-topbar-muted absolute top-[0.3rem] right-[0.3rem]"
        />
      </Button>
      <Button
        variant="ghost"
        size="icon"
        aria-label="Search"
        className="text-topbar-muted hover:bg-topbar-foreground/10 hover:text-topbar-foreground size-8 xl:hidden"
        onClick={() => setOpen(true)}
      >
        <SearchIcon aria-hidden="true" className="size-4" />
      </Button>
    </>
  );
}
