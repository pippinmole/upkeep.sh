import type { EstateHealth } from "@/lib/queries-overview";

// "Needs attention" (docs/NEEDS_ATTENTION.md): the Overview's ranked list of
// actions to take. Each kind of item comes from a provider in registry.ts:
// a small query plus a pure mapper from its rows to items.

// Ranking tier, most urgent first. Within a tier, items keep registry order.
export type AttentionSeverity = "critical" | "high" | "medium" | "low";

// Colour of the item's icon chip.
export type AttentionTone = "kev" | "danger" | "warning" | "info" | "neutral";

// Mapped to a lucide icon by the component, so providers stay plain data.
export type AttentionIcon =
  | "kev"
  | "vuln"
  | "socket"
  | "image"
  | "alert"
  | "stale"
  | "eol"
  | "reboot"
  | "collector"
  | "delivery"
  | "duplicate"
  | "agent"
  | "channel"
  | "waiting";

export type AttentionItem = {
  key: string; // unique per item kind
  severity: AttentionSeverity;
  tone: AttentionTone;
  icon: AttentionIcon;
  title: string;
  subject?: string; // what it is about: host names, collectors, ...
  why: string; // one line: why it matters / what to do
  count: number | null; // null: a state, not a number (e.g. no channel)
  href: string; // where the action is taken
};

export type AttentionQuery = <R>(sql: string) => Promise<R[]>;

export type AttentionContext = {
  // Runs SQL with the workspace id bound to $1 (see owner.ts).
  query: AttentionQuery;
  // The Overview's estate health, already loaded for the Estate card.
  estate: EstateHealth;
};

export type AttentionProvider<T> = {
  key: string;
  load: (ctx: AttentionContext) => Promise<T>;
  map: (data: T) => AttentionItem[];
};

// A provider with its data type erased, for the registry array.
export type AnyAttentionProvider = {
  key: string;
  run: (ctx: AttentionContext) => Promise<AttentionItem[]>;
};

export function defineProvider<T>(p: AttentionProvider<T>): AnyAttentionProvider {
  return { key: p.key, run: async (ctx) => p.map(await p.load(ctx)) };
}
