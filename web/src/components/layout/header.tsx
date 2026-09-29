"use client";

import { Search, Shortcut } from "@/components/search";
import { ThemeSwitch } from "@/components/theme-switch";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

// No title: each page renders its own h1 through PageHeader.
export function Header() {
  return (
    <header className="bg-background/95 sticky top-0 z-10 flex w-full min-w-0 items-center gap-2 border-b px-4 py-3 backdrop-blur sm:gap-3 sm:px-6">
      <Tooltip>
        <TooltipTrigger asChild>
          <SidebarTrigger className="size-8 shrink-0" />
        </TooltipTrigger>
        <TooltipContent className="flex items-center gap-2">
          Toggle sidebar
          <Shortcut keyName="B" className="bg-background/20 text-inherit border-transparent" />
        </TooltipContent>
      </Tooltip>
      <div className="ml-auto flex items-center gap-2">
        <Search />
        <ThemeSwitch />
      </div>
    </header>
  );
}
