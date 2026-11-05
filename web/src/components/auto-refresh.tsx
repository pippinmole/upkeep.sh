"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

// Re-renders the server page every few seconds while it waits for
// something that arrives by itself (the first snapshot).
export function AutoRefresh({ everyMs = 10_000 }: { everyMs?: number }) {
  const router = useRouter();
  useEffect(() => {
    const id = setInterval(() => router.refresh(), everyMs);
    return () => clearInterval(id);
  }, [router, everyMs]);
  return null;
}
