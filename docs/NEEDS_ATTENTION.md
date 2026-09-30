# Needs attention

Status: shipped on the Overview, no migration. Code:
`web/src/lib/attention/` (providers, ranking, ownership) and
`web/src/components/attention/` + `components/overview/needs-attention.tsx`
(UI). Full list at `/dashboard/attention`.

## What it is

The Overview's "Needs attention" card is the list of **actions to take
now**, most urgent first. Every item has:

| field | meaning |
|---|---|
| title | what's wrong, in words ("OS release past end of life on 2 hosts") |
| subject | what it's about: the first few host names (with detail, e.g. the release or the failing collectors), "and N more" |
| count | how many (hosts, findings, alerts…); `null` for a state such as "no channel" |
| severity | `critical` / `high` / `medium` / `low`: the ranking tier |
| why | one line: why it matters or what to do |
| href | where the action is taken: the host's page when there is one host, otherwise the list page, filtered where the list supports it |

Items are ranked by severity, then by registry order (the more important
kinds are listed first). The Overview shows the top **6**, with
"View all N (M more)" linking to `/dashboard/attention`, which shows every
item. With nothing to do, the card says "All clear".

Before this change the card had 8 kinds hard-coded in one component
(`attentionItems()` in `needs-attention.tsx`). It's now a registry of
providers, and 6 new kinds were added (marked **new**).

## Design: a registry of providers

```
lib/attention/
  types.ts        AttentionItem, AttentionProvider<T> {key, load(ctx), map(data)}
  owner.ts        owned(alias) / activeHost(alias): the only place naming the tenant column
  rank.ts         rankItems, capItems, nameList, hostHref (pure)
  registry.ts     ATTENTION_PROVIDERS, in priority order
  index.ts        getAttentionItems(ownerId, estate): runs them, ranks
  providers/      one file per provider
  attention.test.ts
```

- A provider's `load` runs **one small query** (or none: some read the
  estate health the Overview loads anyway for the Estate card), and its
  `map` is a **pure** function from that data to 0..n items, so mapping is
  unit-tested without a database.
- Queries return **aggregates** (counts plus the first 3 names), never the
  whole list, so the cost doesn't grow with the estate's size.
- A provider that throws is logged and left out: one bad query can't take
  the Overview down.
- The runner binds the viewer's workspace id to `$1`; provider SQL filters
  only through `owner.ts`.
- Providers run in parallel, after the Overview's first-run check (a new
  account doesn't run them). The web pool is 5 connections, so the 5
  queries mostly overlap with each other, not with the page's other reads.

### Adding a kind

1. Write `providers/<name>.ts`: SQL filtered with `activeHost("h")` /
   `owned("x")`, returning aggregates; a pure `map`.
2. Add a mapping test to `attention.test.ts`.
3. List it in `registry.ts` at its priority. Give each item a unique `key`
   and pick an icon key (mapped in `components/attention/attention-icon.tsx`).

## Item kinds

| key | severity | source | links to |
|---|---|---|---|
| `kev` | critical | open KEV host package findings (count), hosts, how many have a fix | Vulnerabilities `?kev=1` |
| `host-sockets` **new** | critical | newest snapshot's `collector_status.host_mount = error`: host unix sockets (docker.sock, …) reachable through a recursive `/` mount | the host (one) / Hosts |
| `critical-fixable` **new** | high | open critical host package findings with a fix in the standard archive | Vulnerabilities `?severity=critical&fix=available` |
| `images` | high | image keys with an open critical `vulnerable_image` finding | Images |
| `alerts` | high | firing alert instances (the alerting feature's count, as the sidebar badge) | Alerts |
| `stale` | high | reported hosts whose agents are all offline (the Agents page rule) | the host / Agents |
| `eol` **new** | high | host's OS release (`hosts.os_id` + codename or version) past `distro_releases.eol_date` | the host / Hosts |
| `reboot` | medium | newest snapshot's `reboot_required` | the host / Hosts |
| `collectors` **new** | medium | newest snapshot's collectors with `status = error` (other than `host_mount`), named per host | the host / Hosts |
| `deliveries` | medium | notification deliveries failed in the last 7 days | Delivery log |
| `duplicates` **new** | medium | active hosts with `duplicate_of` set (to an active host) | Hosts (row actions: merge / not a duplicate) |
| `never` | low | non-revoked agents that never pushed | Agents |
| `eol-soon` **new** | low | as `eol`, within 90 days | the host / Hosts |
| `channels` **new** | low | no enabled notification channel (none, or all disabled) | Settings → Channels |
| `waiting` | low | hosts with no snapshot yet | the host / Hosts |

## Candidates considered

Filtered by what the schema and data support today.

| candidate | decision | why |
|---|---|---|
| Host sockets exposed through the host mount | **picked** | The agent already reports it (`host_mount` collector). It's the most severe misconfiguration upkeep can see (root on the host for anything in the agent container), and it's one JSON key on a query we already make. |
| Critical vulnerabilities with a fix available | **picked** | The most actionable vulnerability number: an upgrade fixes it today. Uses existing columns and an existing vulnerabilities filter for the link. (KEV was already an item; it now also says how many have a fix.) |
| OS release past / near end of life | **picked** | `distro_releases.eol_date` exists and hosts carry their OS. No security updates is a slow-burning risk nobody else surfaces. Two items: past (high), within 90 days (low). |
| Failing collectors | **picked** | Silent data gaps: an erroring collector makes a section unknown, not empty, so vulnerability and alert results can be stale. The host header already shows it per host, but nothing showed it fleet-wide. |
| Duplicate hosts awaiting merge or dismissal | **picked** | Flagged by ingest, only visible as a badge in the Hosts table; it doubles counts until someone decides. Cheap. |
| No notification channel (or all disabled) | **picked** | The default SSH rule ships without a channel, so a new account is silently un-notified. Low severity, one count query. |
| Hosts needing a reboot | existing | kept, now a provider |
| Critical / KEV vulnerabilities | existing (KEV) | kept; see "fix available" above |
| Hosts / agents that stopped reporting; agents never connected; hosts waiting for a first report | existing | kept |
| Firing alerts | existing | kept, reusing the alerting count (`getEstateHealth`, the same query shape as the sidebar badge) |
| Failed notification deliveries | existing | kept |
| Images in use with critical vulnerabilities | existing | kept |
| Images on an EOL base OS | deferred | Needs the image's base OS release (`image_sbom_state` / SBOM distro), matched to `distro_releases`; per-image, not per-host, and the join is heavier. Follow-up. |
| Outdated agent versions | deferred | The server doesn't know the latest released agent version (no release feed or constant); comparing to the newest agent in the account is misleading. Needs a version source first. |
| Enrollment tokens unused / about to expire | rejected | Tokens are one-time and short-lived, and expired ones are deleted by `credential_cleanup`; an unused token isn't an action. |
| Vulnerability feeds stale or failing to sync | deferred | `feed_sync_state` is instance-wide, not per account: it's an operator concern, and should decide which role (docs/MEMBERS.md) sees it. |
| Remote (SSH) collection failing | deferred | `agent_hosts.last_error` for enabled ssh assignments; small, but remote hosts are new and the error already shows on the Agents page. Good next provider. |
| Credential rotation requested but not picked up | deferred | `agent_credentials.rotate_requested_at` older than a few push intervals. Rare; low value for now. |
| Alert rules with no channel while alerts fire | deferred | Partly covered by "no channel"; a per-rule version needs the rule/channel join and competes with the alerting UI's own hints. |
| Listening on all interfaces / exposed ports | deferred | That's what alert rules are for (the default SSH rule); duplicating it here would give two sources of truth. Exposure classification is Phase 1.6. |
| Unattended upgrades disabled | deferred | Collected (`unattended_upgrades`) but not stored as a queryable fact yet. |
| Report schedule failures | deferred | Reports are delivered through channels, so failures already show as failed deliveries. |

## Follow-ups

Tracked in [tasks/needs-attention.md](tasks/needs-attention.md).

## Ownership

Per workspace (migration 0023, docs/MEMBERS.md). The new providers' SQL
names the tenant column only in `owner.ts` (`OWNER_COLUMN =
"workspace_id"`); the existing estate-derived items come from
`getEstateHealth` in `lib/queries-overview.ts`. Needs attention is
read-only, so it needs no `requireAdmin()`.
