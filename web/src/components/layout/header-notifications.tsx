"use client";

import { Bell } from "lucide-react";
import * as React from "react";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ScrollArea } from "@/components/ui/scroll-area";

type HeaderNotification = {
  id: string;
  title: string;
  description: string;
  time: string;
  read: boolean;
};

// This is a security-monitoring app, not a demo store — there is no
// notification feed wired up yet, so this list starts empty rather than
// being seeded with fabricated data that would be actively misleading.
const INITIAL_NOTIFICATIONS: HeaderNotification[] = [];

export function HeaderNotifications() {
  const [notifications] = React.useState(INITIAL_NOTIFICATIONS);
  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          id="header-notifications-trigger"
          variant="outline"
          size="icon"
          className="relative size-9"
          aria-label={
            unreadCount
              ? `Notifications, ${unreadCount} unread`
              : "Notifications"
          }
        >
          <Bell className="size-4" aria-hidden="true" />
          {unreadCount > 0 ? (
            <span className="bg-destructive text-destructive-foreground absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full px-1 text-[10px] font-medium tabular-nums">
              {unreadCount > 9 ? "9+" : unreadCount}
            </span>
          ) : null}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="w-80 p-0" align="end">
        <DropdownMenuLabel className="px-3 py-2 text-sm font-normal">
          <span className="font-semibold">Notifications</span>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        {notifications.length === 0 ? (
          <div className="text-muted-foreground flex flex-col items-center justify-center gap-1 px-3 py-8 text-center text-sm">
            <Bell className="mb-1 size-5 opacity-40" aria-hidden="true" />
            <p>No notifications yet</p>
          </div>
        ) : (
          <ScrollArea className="h-[min(320px,50vh)]">
            <div className="flex flex-col py-1">
              {notifications.map((n) => (
                <div key={n.id} className="px-3 py-2.5">
                  <p className="text-sm leading-tight">{n.title}</p>
                  <p className="text-muted-foreground text-xs leading-snug">
                    {n.description}
                  </p>
                </div>
              ))}
            </div>
          </ScrollArea>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
