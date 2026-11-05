# Machines home page and top bar: design

Status: approved for planning on branch `pippinmole/chore-checkout-latest-main`
(not going to `main` yet). First slice of a wider web UI overhaul.

## 1. Why

The dashboard is too chaotic. After logging in, the user wants to answer one
question first: **how many vulnerabilities does each machine have?** Their
second step is to open one machine and work through its vulnerabilities.
Today's Overview answers neither directly: it is a stack of cards (needs
attention, estate health, four metric tiles, urgent vulns, severity bars,
container images, latest report), and the machine list lives two clicks away
under Hosts, next to a separate Agents page.

The target feel is Tailscale's admin console: a slim top bar with tabs, and a
calm list of machines as the home page. The user asked for a radical change:
new colours, layout and component styles, and new data fetching where the
layout needs it. We are not copying Tailscale's look, only its structure.

Wider context (not built here): upkeep.sh will also be offered as SaaS, where
people sign up, get their own workspace and register agents that report to
the hosted API. Every query is already scoped by `workspaceId`, and an
install has exactly one workspace today (`server/migrations/0023_members.up.sql`).
This slice must not make that harder; see section 7.

## 2. Goals

- The home page (`/dashboard`) is the **Machines** list: one row per host,
  showing its open vulnerabilities by severity.
- A new **top bar with tabs** replaces the sidebar on every dashboard page.
- A new visual identity, "Persimmon" (section 5), in light and dark, applied
  through the shared theme tokens so every page picks it up.
- Clicking a machine goes to its existing machine page
  (`/dashboard/hosts/[hostId]`), the user's step 2.

## 3. Non-goals

- Redesigning other pages' layouts (Vulnerabilities, Images, Alerts, Reports,
  Settings, the machine page). They get the new tokens and top bar for free
  and keep their current layout. **Agreed with the user: it is fine for them
  to look half-converted for a while.**
- SaaS signup, workspace creation or switching, billing.
- Any Go server, API or database change. This is web-only, like the previous
  UX overhaul (`docs/design/ux-overhaul.md`).
- Renaming URLs. Routes stay `/dashboard/hosts/...`; only the UI says
  "Machines" (my call: avoids churn across ~30 files that link to hosts, and
  URL renames can come with a later slice).

## 4. Anti-goals (fails even if it "works")

- The home page grows back into a dashboard of cards and tiles. One summary
  line under the title is the ceiling.
- Host package and container image vulnerability counts are added together.
  They are fixed differently and the domain model keeps them apart
  (`docs/DOMAIN_MODEL.md` §3.6).
- The new palette uses the brand accent for ordinary buttons so that
  "critical" and "click me" look alike.
- It looks like a Tailscale clone.

## 5. Visual identity: Persimmon

Chosen by the user from four options (mockup:
`.superpowers/brainstorm/*/content/color-schemes.html`, option 1).

"Paper and ink": a warm off-white page, a near-black top bar, white surfaces
for tables, and a persimmon accent. Reference values (sRGB, convert to OKLCH
to match `globals.css`):

| Token          | Light     | Dark      | Use |
|----------------|-----------|-----------|-----|
| page bg        | `#f6f4ef` | `#151412` | `--background` |
| surface        | `#ffffff` | `#1d1c19` | `--card`, table bodies |
| ink            | `#1c1b18` | `#ece8df` | `--foreground` |
| muted ink      | `#7a756a` | `#9a9488` | `--muted-foreground` |
| hairline       | ink @ 8%  | white @ 7% | `--border` |
| top bar        | `#1c1b18` | `#0d0c0b` | new `--topbar`, `--topbar-foreground` |
| accent         | `#ff6a3d` | `#ff7a50` | active tab underline, focus ring, links |
| primary button | ink on paper | paper on ink | `--primary` stays neutral (anti-goal) |
| critical       | `#e5482b` solid, white text | `#ff6a3d`, dark text | `--sev-critical` |
| high           | `#ffd8c9` tint, `#9a2f0b` text | `#5a2a18`, `#ffc4ad` | `--sev-high` |
| medium         | `#efe9dc` tint, `#6b5d3d` text | `#2c2922`, `#c9bfa8` | `--sev-medium` |
| ok / online    | `#2fa36b` | `#43c285` | `--success` |
| stale          | `#d9a400` | `#e8b923` | `--warning` |

Low and unknown severities, KEV, info and `--accent-pro` get values in the
same family; that's the builder's call. Contrast must meet WCAG AA for text.
Light and dark both ship; the existing `next-themes` switch stays.

Component style: flat, hairline borders, small radii (6–9px), no drop
shadows on cards, tabular numerals for every count. Severity counts are
compact **count pills** (critical / high / medium), as in the mockup. The
sidebar-specific tokens (`--sidebar-*`) are removed with the sidebar.

## 6. What gets built

### 6.1 Top bar (all dashboard pages)

Replaces `AppSidebar` + `Header` in `web/src/app/dashboard/layout.tsx`.

- **Left:** the upkeep wordmark, then the **workspace name** (read from
  `workspaces.name`). A plain label for now; it is the spot where a
  workspace switcher will go for SaaS.
- **Tabs, in order:** Machines (`/dashboard`) · Vulnerabilities · Images ·
  Alerts · Reports · Settings. The active tab gets the accent underline. A tab
  is active for its route and everything under it. Machines is also active on
  `/dashboard/hosts/*`.
- **Right:** the ⌘K search trigger (existing `Search` and `CommandMenu`), a
  firing-alerts indicator that shows only when alerts are firing (links to
  Alerts), and the avatar menu (account, theme, log out; reuse `NavUser`
  pieces).
- **Badges:** drop the per-tab badges. Firing alerts is the only signal kept.
- **Removed from the bar:** Packages, Swarm and Agents. Packages and Swarm
  stay reachable from ⌘K and from links on machine and image pages. Agents
  moves to a section in Settings (the route `/dashboard/agents` keeps working
  and the Settings section nav links to it; whether it is physically moved
  under `/dashboard/settings/` is the builder's call). Swarm stays
  `swarmOnly` in the command menu.
- **Phone width:** the tabs become a horizontally scrolling row under the
  bar. No hamburger menu.
- `nav-config.ts` stays the single source for the tabs and the command menu.
  Its groups become a flat tab list plus a "more" list (Packages, Swarm,
  Agents) that only the command menu shows.

### 6.2 Machines home page (`/dashboard`)

Replaces the Overview entirely.

- **Header:** "Machines" title; one summary line under it, e.g.
  "12 machines · 3 with critical vulnerabilities" (exact wording is the
  builder's); an **Add machine** button (existing `AddHostDialog`, retitled).
- **Search and filters** above the list: one text box matching name, label,
  OS and IP, plus filters for status (online / stale / never reported),
  OS, and "has critical" / "has KEV". Filter state lives in the URL
  (`search-params.ts` conventions) so it can be shared.
- **The list:** one row per non-archived machine. **Sort is always
  alphabetical by hostname** (user decision), no sort control. Columns:
  1. **Machine:** status dot (online / stale / never reported), hostname
     (label if set, hostname secondary), IP, and how it is collected
     ("local agent" or "via <agent name>"). Small inline tags when they
     apply: "Possible duplicate", "Merged into X", "Reboot required".
     *Several agents per machine (my call):* the dot is online if any agent
     is online, stale if some non-revoked agent exists but none is online,
     and never reported otherwise, the same rule `getNavCounts` uses. A
     machine whose agents are all revoked shows as stale with a "No active
     agent" tag. The label names the first non-revoked agent, local before
     SSH before WinRM, plus "+N" if there are more.
  2. **OS:** e.g. "Ubuntu 22.04".
  3. **Last seen:** relative time.
  4. **Open vulnerabilities:** critical / high / medium count pills for
     **host packages only**, with a "N KEV" marker when non-zero. If the
     machine runs containers with vulnerable images, a small secondary
     "+N in images" figure; it is never added to the pills (my call, per the
     anti-goal). *N (my call):* the number of distinct open vulnerabilities
     across the images that the host's **current containers** run (via
     `host_containers` → `host_images` → `image_scores()`, as in
     `queries-overview-images.ts`). Tooltip gives the image count and how
     many of N are critical. A machine with nothing open in either shows a
     quiet "No open vulnerabilities" instead of zeros.
  5. A **"⋯" row menu** (user decision; section 6.2.1). The rest of the row
     links to `/dashboard/hosts/[hostId]`; the menu button must not trigger
     the row link.
- **Filters and the summary line vs. images (my call):** "has critical" and
  "has KEV" match a machine if its host packages **or** its running images
  have one, so no at-risk machine is hidden; the filter chip says so
  ("Critical, packages or images"). The summary line counts the same way.
  The pills themselves stay host-packages-only.
- **Archived machines** are hidden; a small "Show N archived" toggle at the
  bottom reveals them (my call). Unarchive is in their row menu.

#### 6.2.1 Row menu

Built from the existing `web/src/app/dashboard/hosts/host-row-actions.tsx`
and the server actions in `web/src/app/dashboard/manage-actions.ts`
(rename, archive, merge, dismiss duplicate, delete). The changing items are
admin-only and hidden from read-only members, as today. Items, in order:

1. Copy hostname · Copy IP (IP only when known). **New.**
2. Export vulnerabilities (CSV): a link to the existing
   `/dashboard/hosts/[hostId]/vulnerabilities/export` route. **New**, and
   visible to members too, since it is read-only. That makes the menu itself
   visible to members, with only copy and export in it.
3. Rename.
4. Merge into <original> · Not a duplicate: only when flagged as a possible
   duplicate.
5. Archive, or Unarchive when archived.
6. Divider, then **Delete** in danger colour, behind the existing confirmation
   dialog that asks for the hostname to be typed.

Not included (user decision): "Remove SSH target".
- **Empty states:**
  - No machines and no agent: the list area becomes a first-run panel built
    around Add machine (replaces `FirstRunHero`).
  - Machines exist but none has reported: rows show "Waiting for first
    report" (replaces `WaitingForFirstReport`).
- **Freshness:** the page refreshes on an interval, as `auto-refresh.tsx`
  does today.

Removed from the home page (and their components deleted if nothing else
uses them): `NeedsAttention`, `EstateCard`, metric tiles, `UrgentVulns`, the
severity card, `ContainerImagesSection`, `LatestReportCard`,
`GettingStarted`. The `/dashboard/attention` page goes too; it redirects to
`/dashboard`. `/dashboard/hosts` (the old list) redirects to `/dashboard`.

### 6.3 Data fetching

One new server-side query, e.g. `getMachines(workspaceId)` in
`web/src/lib/`, returning everything a row needs in **one SQL round trip**:
host identity, OS, status, last seen, collection mode and agent name, IP from
the latest snapshot, **open vulnerable-package counts per severity**
(critical, high, medium, low), KEV count, the running-image figures from
6.2 (distinct open vulns, how many critical, any KEV, image count), the
duplicate / merged / reboot-required flags and the archived state (the row
menu and tags need them; `getHosts` already selects most of these). `getHosts` today only returns the total, KEV and
top severity (`HOST_FINDINGS_SQL` in `web/src/lib/queries.ts`); extend that
pattern with `count(*) FILTER (WHERE severity = ...)`. Order by hostname in
SQL.

The page is a server component that awaits that query (plus workspace name
and onboarding state for empty states). Search and filters run on the client
over the fetched rows: a workspace's machine count is small enough today. If
that stops being true, push the filters into SQL; note it, don't build it.

Nav data: `getNavCounts` shrinks to what the top bar needs (`firingAlerts`,
`hasSwarm`). It also has to fetch the workspace name.

## 7. Keeping SaaS possible

- Every new query takes `workspaceId` from `requireViewer()`, like today.
- The workspace name is read from the database, never hard-coded, and sits in
  the bar where a switcher will go.
- Copy says "machine" and "workspace", not "server" or "install".
- No per-install assumptions in the new components (no reading of a single
  global workspace).

## 8. How the work is done

- Skills installed in `web/.agents/skills/` and to be used:
  **frontend-design** while designing components; **vercel-composition-patterns**
  for the component kit (top bar, tabs, machine row, count pill);
  **web-design-guidelines** as a review step on each finished screen;
  **vercel-react-best-practices** for data fetching and rendering.
- Read `web/AGENTS.md` first: this Next.js version differs from training data.
- Verify locally (CI is unavailable): web typecheck, lint, test and build,
  and check both themes and phone width in a browser.
- Mockups for reference: `.superpowers/brainstorm/*/content/machines-layout.html`
  (option A) and `color-schemes.html` (option 1).

## 9. Left to the builder

Exact OKLCH values, low/unknown/KEV tones, type scale, icon choices, summary
line wording, filter control style, the empty-state copy, test strategy for
the new query, and whether Agents physically moves under Settings.
