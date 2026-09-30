import { pool } from "@/lib/db";
import type { EstateHealth } from "@/lib/queries-overview";

import { rankItems } from "./rank";
import { ATTENTION_PROVIDERS } from "./registry";
import type { AttentionContext, AttentionItem, AnyAttentionProvider } from "./types";

export type { AttentionItem } from "./types";

// Runs every provider (in parallel; each is one small query or none) and
// ranks the result. A provider that fails is logged and left out, so one
// broken query can't take the Overview down.
export async function getAttentionItems(
  workspaceId: string,
  estate: EstateHealth,
  providers: AnyAttentionProvider[] = ATTENTION_PROVIDERS,
): Promise<AttentionItem[]> {
  const ctx: AttentionContext = {
    query: async <R>(sql: string) => (await pool.query(sql, [workspaceId])).rows as R[],
    estate,
  };
  const lists = await Promise.all(
    providers.map((p) =>
      p.run(ctx).catch((err: unknown) => {
        console.error(`needs attention: provider ${p.key} failed`, err);
        return [];
      }),
    ),
  );
  return rankItems(lists.flat());
}
