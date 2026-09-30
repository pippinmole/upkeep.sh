import type { AttentionItem, AttentionSeverity } from "./types";

const SEVERITY_ORDER: Record<AttentionSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// Most urgent first: by severity, then in the order the items were produced
// (registry order, which lists the more important kinds first). Stable.
export function rankItems(items: AttentionItem[]): AttentionItem[] {
  return items
    .map((item, i) => ({ item, i }))
    .sort((a, b) => SEVERITY_ORDER[a.item.severity] - SEVERITY_ORDER[b.item.severity] || a.i - b.i)
    .map((x) => x.item);
}

// The top `max` items and how many more there are.
export function capItems(
  items: AttentionItem[],
  max: number,
): { shown: AttentionItem[]; hidden: number } {
  return { shown: items.slice(0, max), hidden: Math.max(0, items.length - max) };
}

export const MAX_NAMES = 3;

// "a, b, c and 2 more" from the first names and the total.
export function nameList(names: string[], total = names.length, max = MAX_NAMES): string {
  const shown = names.slice(0, max);
  const more = total - shown.length;
  return more > 0 ? `${shown.join(", ")} and ${more} more` : shown.join(", ");
}

// One host: its page. Several: the list where they are.
export function hostHref(count: number, firstId: string | null, many: string): string {
  return count === 1 && firstId ? `/dashboard/hosts/${firstId}` : many;
}

export function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}
