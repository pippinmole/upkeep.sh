"use client";

import { useEffect, useState } from "react";

import type { SearchResponse } from "@/lib/search/map";
import { normalizeQuery } from "@/lib/search/query";

export const SEARCH_DEBOUNCE_MS = 200;

export type GlobalSearchState = {
  data: SearchResponse | null; // the last answer, kept while the next loads
  loading: boolean;
  error: boolean;
};

type Answer = { q: string; data: SearchResponse | null; error: boolean };

const IDLE: GlobalSearchState = { data: null, loading: false, error: false };

// Debounced GET /api/search for the command menu. A new keystroke cancels
// the pending timer and aborts the request in flight, so answers never
// arrive out of order. Queries under MIN_QUERY_LENGTH never leave the
// browser. Loading is derived: the current query has no answer yet.
export function useGlobalSearch(query: string, enabled: boolean): GlobalSearchState {
  const [answer, setAnswer] = useState<Answer | null>(null);
  const q = enabled ? normalizeQuery(query) : null;

  useEffect(() => {
    if (!q) return;
    const ctrl = new AbortController();
    const timer = setTimeout(async () => {
      try {
        const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`, {
          signal: ctrl.signal,
          headers: { Accept: "application/json" },
        });
        if (!res.ok) throw new Error(`search: HTTP ${res.status}`);
        setAnswer({ q, data: (await res.json()) as SearchResponse, error: false });
      } catch {
        if (!ctrl.signal.aborted) setAnswer({ q, data: null, error: true });
      }
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      clearTimeout(timer);
      ctrl.abort();
    };
  }, [q]);

  if (!q) return IDLE;
  const loading = answer?.q !== q;
  return { data: answer?.data ?? null, loading, error: !loading && !!answer?.error };
}
