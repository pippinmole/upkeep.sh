import { HeaderNotifications } from "@/components/layout/header-notifications";
import { Search } from "@/components/search";
import { ThemeSwitch } from "@/components/theme-switch";
import { SidebarTrigger } from "@/components/ui/sidebar";

export function Header({ title = "Overview" }: { title?: string }) {
  return (
    <header className="bg-background grid w-full min-w-0 grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-2 border-b px-4 py-4 sm:gap-3 sm:px-6">
      <SidebarTrigger className="size-8 shrink-0" />
      <div className="min-w-0">
        <h1 className="truncate text-base font-medium">{title}</h1>
      </div>
      <div className="flex items-center gap-2">
        <Search className="hidden sm:flex" />
        <HeaderNotifications />
        <ThemeSwitch />
      </div>
    </header>
  );
}
