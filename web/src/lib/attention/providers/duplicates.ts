import { activeHost } from "../owner";
import { MAX_NAMES, nameList } from "../rank";
import type { AttentionProvider } from "../types";

// Hosts flagged as a possible duplicate (same machine identity as another,
// active host: a cloned VM, or an agent reinstalled before the old one went
// quiet). Ingest never merges them; the Hosts table's row actions do
// ("Merge into …" or "Not a duplicate"). "Not a duplicate" clears
// duplicate_of, so a flag here is always still awaiting a decision.

export type DuplicateData = { n: number; names: string[] };

const SQL = `
  SELECT count(*) AS n,
         (array_agg(coalesce(h.label, h.hostname) ORDER BY h.created_at, h.id))[1:${MAX_NAMES}] AS names
  FROM hosts h
  JOIN hosts o ON o.id = h.duplicate_of AND o.archived_at IS NULL
  WHERE ${activeHost("h")} AND h.duplicate_of IS NOT NULL`;

export const duplicates: AttentionProvider<DuplicateData> = {
  key: "duplicates",
  load: async (ctx) => {
    const [r] = await ctx.query<{ n: string; names: string[] | null }>(SQL);
    return { n: Number(r?.n ?? 0), names: r?.names ?? [] };
  },
  map: ({ n, names }) =>
    n > 0
      ? [
          {
            key: "duplicates",
            severity: "medium",
            tone: "info",
            icon: "duplicate",
            title:
              n === 1 ? "Possible duplicate host to review" : "Possible duplicate hosts to review",
            subject: nameList(names, n),
            why: "Same machine identity as another host: merge them, or mark them as different.",
            count: n,
            href: "/dashboard/hosts",
          },
        ]
      : [],
};
