"use client";

import { Loader2 } from "lucide-react";

import { MIN_QUERY_LENGTH } from "@/lib/search/query";

// The line above the results: searching, failed, too short or nothing
// found. Not a cmdk item, so arrow keys skip it.
export function SearchStatus({
  query,
  loading,
  error,
  empty,
}: {
  query: string;
  loading: boolean;
  error: boolean;
  empty: boolean;
}) {
  const q = query.trim();
  let text: React.ReactNode = null;
  if (!q) return null;
  if (loading) {
    text = (
      <>
        <Loader2 className="size-3.5 animate-spin" /> Searching…
      </>
    );
  } else if (error) {
    text = "Search failed. Try again.";
  } else if (q.length < MIN_QUERY_LENGTH) {
    text = `Type at least ${MIN_QUERY_LENGTH} characters to search your data.`;
  } else if (empty) {
    text = <>No hosts, vulnerabilities, packages, images, containers or agents match.</>;
  }
  if (!text) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className="text-muted-foreground flex items-center gap-2 px-4 py-2 text-xs"
    >
      {text}
    </div>
  );
}
