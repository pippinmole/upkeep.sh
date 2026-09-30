import { activeHost } from "../owner";
import { hostHref, MAX_NAMES, nameList, plural } from "../rank";
import type { AttentionItem, AttentionProvider } from "../types";

// Hosts on an OS release past (or within 90 days of) the end of its
// security support: distro_releases.eol_date (Debian incl. LTS, Ubuntu
// standard support excl. ESM, Alpine), matched on the host's current OS
// (hosts.os_id + codename, or version: Alpine reports no codename).

export const EOL_SOON_DAYS = 90;

export type EolGroup = {
  n: number;
  names: string[]; // first few, "name (Ubuntu 20.04)"
  firstId: string | null;
};

export type EolData = { past: EolGroup; soon: EolGroup };

const SQL = `
  WITH eol AS (
    SELECT DISTINCT ON (h.id)
           h.id, coalesce(h.label, h.hostname) AS name, dr.eol_date,
           initcap(dr.distro) || ' ' || dr.version AS release
    FROM hosts h
    JOIN distro_releases dr
      ON dr.distro = h.os_id AND (dr.codename = h.os_codename OR dr.version = h.os_version)
    WHERE ${activeHost("h")}
      AND dr.eol_date < current_date + ${EOL_SOON_DAYS}
    ORDER BY h.id, (dr.codename = h.os_codename) DESC
  )
  SELECT eol_date < current_date AS past, count(*) AS n,
         (array_agg(name || ' (' || release || ')' ORDER BY eol_date, lower(name)))[1:${MAX_NAMES}] AS names,
         (array_agg(id ORDER BY eol_date, lower(name)))[1] AS first_id
  FROM eol
  GROUP BY 1`;

const EMPTY: EolGroup = { n: 0, names: [], firstId: null };

export const endOfLife: AttentionProvider<EolData> = {
  key: "eol",
  load: async (ctx) => {
    const rows = await ctx.query<{
      past: boolean;
      n: string;
      names: string[];
      first_id: string;
    }>(SQL);
    const group = (past: boolean): EolGroup => {
      const r = rows.find((x) => x.past === past);
      return r ? { n: Number(r.n), names: r.names, firstId: r.first_id } : EMPTY;
    };
    return { past: group(true), soon: group(false) };
  },
  map: ({ past, soon }) => {
    const items: AttentionItem[] = [];
    if (past.n > 0) {
      items.push({
        key: "eol",
        severity: "high",
        tone: "warning",
        icon: "eol",
        title: `OS release past end of life on ${plural(past.n, "host", "hosts")}`,
        subject: nameList(past.names, past.n),
        why: "The distribution no longer ships security updates for it: upgrade the release.",
        count: past.n,
        href: hostHref(past.n, past.firstId, "/dashboard/hosts"),
      });
    }
    if (soon.n > 0) {
      items.push({
        key: "eol-soon",
        severity: "low",
        tone: "info",
        icon: "eol",
        title: `OS release reaches end of life within ${EOL_SOON_DAYS} days`,
        subject: nameList(soon.names, soon.n),
        why: "Plan the release upgrade before security updates stop.",
        count: soon.n,
        href: hostHref(soon.n, soon.firstId, "/dashboard/hosts"),
      });
    }
    return items;
  },
};
