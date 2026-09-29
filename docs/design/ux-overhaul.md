# UX overhaul: audit and design plan

Status: implemented on branch `ux-overhaul` (one PR). This file is the
reviewer's guide: what was wrong, what we decided and why, and the order
the work was done in. Everything here is UI-level. No Go server code, API
fields or DB columns were renamed, and there are no migrations.

## 1. How the audit was done

Five audits ran in parallel, each read-only against the code: IA and nav,
onboarding and empty states, visual language, page layouts and the
Overview, and tables, search, a11y and responsive. The Chrome browser
bridge didn't respond in this session, so the audit is code-based rather
than from screenshots.

## 2. Findings (de-duplicated)

### Bugs several audits found independently
- **Every page was titled "Overview".** `layout.tsx` rendered `<Header />`
  without a title, and `header.tsx` defaulted to an `<h1>Overview</h1>`.
  With each page's own `<h1>`, every page had two h1s, and one was wrong.
- **The host detail "All hosts" back link went to `/dashboard/agents`.**
- **The notification bell was a stub.** It always said "No notifications
  yet", even when deliveries had failed. In a security product, a dead
  alert control teaches people to ignore it.
- **An empty estate read as good news.** With 0 hosts the Overview said
  "No known-exploited vulnerabilities" and "No host is waiting for a
  reboot".

### Information architecture
- The sidebar was one flat "General" group of 8 items. It mixed inventory
  (Hosts, Images, Packages, Swarm), triage (Vulnerabilities) and plumbing
  (Agents, Alerts).
- Agents sat second, above Vulnerabilities, although it's plumbing you
  visit during onboarding or when something breaks.
- Reports, a core output of the product, had no nav entry. Schedules and
  past reports sat three levels deep under Settings → Notification
  settings, and a report page lit up no nav item.
- "Notification settings" inside a page called "Settings" repeated itself.
  The page only holds channels, and the Alerts copy already calls them
  "channels".
- Icons were backwards: Hosts used `Monitor` (a desktop) and Agents used
  `Server`. Three different bells (Alerts, Notification settings, header)
  meant three different things.
- No nav badges, although the data for "needs action" counts exists.
- The command menu only listed pages. It had no hosts and no "go to CVE",
  always showed Swarm, and hard-coded ⌘K for Windows users too. Search
  was hidden below `sm`.

### Onboarding
- There was no first-run path. Nothing said what to do in which order
  (agent → first snapshot → Docker → channel → rule → report).
- The enrollment dialog ended at "run this command". It had no
  waiting/connected feedback, unlike the remote-target flow, which does
  poll.
- "Add host" and "Register agent" opened the same panel under different
  titles.
- Empty states were hand-rolled 7+ times. Several had no action, and some
  put their action only in the page header.
- Copy-once secrets were styled as errors (`destructive`).
- Login and signup were unstyled raw inputs (`bg-black`, broken in dark
  mode). Signup errors threw to an error boundary, and neither page
  linked to the other.

### Visual language
- Severity colour had one source (`vuln/badges.tsx`). Nothing else did.
  Status colours were raw Tailwind literals in about 20 files: 3 amber
  recipes and 2+ emerald ones for the same meanings.
- There were no semantic tokens in `globals.css` beyond `--destructive`.
- `SeverityBars` on the Overview drew every severity in the same grey.
- `Badge` rendered a `<div>` (invalid inside `<span>`s) and defaulted to
  `font-semibold`, which almost every call site overrode.
- The agent status dot relied on colour alone.
- Domain objects had no visual identity: no OS logos, registry marks or
  channel icons. OS names were duplicated and inconsistent ("Rhel" vs
  "RHEL").
- 16 hand-rolled page headers with different back links, spacing and
  badge rows.

### Tables and a11y
- Numeric columns in `DataTable` couldn't be right-aligned.
- Sort state wasn't announced (`aria-sort`).
- Truncated cells had no `title`.
- The column-visibility button was hidden below `lg`.

## 3. Decisions

### Renames (UI only)
| Before | After | Why |
|---|---|---|
| Settings → "Notification settings" | Settings → **Channels** | The page holds channels only; "notification settings" under "Settings" said nothing. |
| Report schedules under Settings | Top-level **Reports** | Reports are a product output, not configuration. |

**Kept on purpose:**
- **Hosts / Agents.** DOMAIN_MODEL.md defines them precisely: a host is a
  machine, an agent is a collector, and they are many-to-many through SSH
  remote targets. The CLI, README and protocol all say "agent". The
  confusion came from icons, ordering and copy, which we fixed instead.
  Agents now uses a `RadioTower` icon and the subtitle "Collectors that
  report on your hosts".
- **Swarm, Images, Alerts** are the words users search for.

### Routes
| From | To |
|---|---|
| `/dashboard/settings/notifications` | `/dashboard/settings/channels` (permanent redirect) |
| `/dashboard/settings/notifications/reports/:id` | `/dashboard/reports/schedules/:id` (permanent redirect) |
| (new) | `/dashboard/reports`: schedules plus recent reports |
| `/dashboard/reports/:id` | unchanged; emails and ntfy link to it |

### Navigation tree
```
Overview            LayoutDashboard
SECURITY
  Vulnerabilities   ShieldAlert     badge: open KEV + critical vulns (red)
ESTATE
  Hosts             Server          badge: stale hosts (amber)
  Images            Container
  Packages          Package
  Swarm*            Boxes           (*only when a host is in a Swarm; last so nothing jumps)
OPERATIONS
  Alerts            BellRing        badge: failed deliveries, 7 days (red)
  Reports           FileChartColumn
  Agents            RadioTower      badge: stale / never-seen agents (amber)
footer: Settings (→ Channels), user menu
```
- Badges mean "needs action", never totals, and are hidden at 0. In
  icon-collapsed mode a badge becomes a coloured dot.
- One `nav-config.ts` feeds the sidebar, the command menu and the page
  titles.
- No collapsible sub-items. Sub-sections stay as in-page tabs, because
  with about 10 items nesting only adds clicks.

### Shell
- The global header loses its h1. It now holds the sidebar trigger, search
  (an icon button on mobile, and "Ctrl K" or "⌘K" depending on platform)
  and the theme switch.
- The fake bell is removed. Failed deliveries now appear as a nav badge on
  Alerts.
- Each page owns its `<PageHeader>`, which renders breadcrumbs on detail
  pages. That gives one h1 per page.

### Visual system
- Semantic tokens in `globals.css`, in light and dark:
  - `--sev-{critical,high,medium,low,unknown}` (+`-fg`)
  - `--kev`
  - `--success`, `--warning`, `--danger`, `--info` (+`-fg`)
  - `--accent-pro`

  They are mapped in `@theme inline`, so classes like
  `bg-sev-critical/10 text-sev-critical-fg` work.
- `Badge` renders a `span`, defaults to `font-medium`, and gains the
  variants `success | warning | danger | info | neutral | dashed`.
- `components/status.tsx` adds `StatusBadge` and `StatusDot`, which always
  carry sr-only text. Domain tone maps (agent status, container state,
  delivery status) mean no page writes colour classes again.
- `components/brand/` adds `OsLogo`, `RegistryLogo`, `ChannelIcon` and
  `EcosystemIcon`, backed by vendored simple-icons paths (CC0) in one
  module:
  - Monochrome `currentColor` in tables; brand colour only in headers.
  - Lucide fallbacks for anything unknown or not in simple-icons (e.g.
    AWS).
  - No new dependency.
- `lib/os.ts` is the one place OS names live.
- New shared components:
  - `components/ui/card.tsx` (shadcn)
  - `components/empty-state.tsx`
  - `components/layout/page-header.tsx` (breadcrumbs, title, badges,
    meta line, description, actions)
- Severity bars on the Overview use the severity colours.

### Overview (redesigned)
```
Overview · Estate health and what needs attention now      [Add host]
[Getting started checklist: until the required steps are done, hideable]
┌ Needs attention (ranked) ───────────────┐ ┌ Estate ───────────────┐
│ KEV vulns on N hosts        → vulns     │ │ N hosts: ok/stale/⚠   │
│ Stale hosts: a, b           → host      │ │ host health grid      │
│ Reboot required: c, d       → host      │ │ (one square per host) │
│ Images with critical vulns  → images    │ │ containers · images   │
│ Failed deliveries (7d)      → alert log │ └───────────────────────┘
│ ✓ "All clear" when empty                │
└─────────────────────────────────────────┘
[Open vulns · KEV · Critical+High · No fix yet]   stat row, coloured
┌ Most urgent vulnerabilities ────────────┐ ┌ By severity (colour bars) ┐
┌ Container images ───────────────────────┐ ┌ Latest report ────────────┐
```
- With **0 hosts**, the whole page is a Getting-started hero instead of a
  wall of zeros.
- "Stale" uses the agent-health rule, so the Overview and Agents pages
  agree.

### Onboarding
- The **Getting started checklist** is backed by `getOnboardingState`
  (one SQL round trip of `EXISTS`). Steps:
  1. install agent
  2. first host reported
  3. Docker collection (optional)
  4. add a channel
  5. create an alert rule
  6. schedule a report

  Each step has a done / in-progress / todo state, and there is one
  primary action for the first incomplete step. "Hide" is a per-browser
  `localStorage` convenience; no migration.
- **Enrollment** polls and shows three states: waiting for the agent,
  enrolled and waiting for the first snapshot, then connected. The
  connected state offers "Open host" and "Next: set up alerts".
- "Add host" is the primary entry. The Agents page button reads "Install
  an agent" and explains the agent ↔ host relationship.
- A shared `EmptyState` is used everywhere, with the action inline and
  prerequisites shown as steps.
- Copy-once secrets use the warning tone, not destructive.
- Login and signup use Card/Label/Input/Button and show inline errors via
  `useActionState`, and each links to the other.

### Tables
- `DataTable`:
  - `columnDef.meta.className` for right-aligned numeric columns
  - `aria-sort` on sortable headers
  - titles on truncated cells
- The column-visibility button shows as an icon on small screens.

## 4. Work order (to avoid collisions)
1. **Foundation.** Tokens, `Badge`, Card, `StatusBadge`, `EmptyState`,
   `PageHeader`, severity re-skin. In parallel: brand marks, `lib/os.ts`,
   `registryOf`, `DataTable` a11y.
2. **In parallel, split by file ownership:**
   - Shell and nav: `components/layout/*`, command menu, search, nav
     counts, `dashboard/layout.tsx`.
   - Routes: the Reports index, the Channels rename, redirects, and the
     alerts/settings/reports pages.
   - Overview and onboarding: the overview page and components, the
     enroll dialog, the add-host dialog, auth pages.
   - Hosts and Agents pages.
   - Images, Packages, Vulnerabilities and Swarm pages.
3. **Verify:** lint, format, tsc, test, build.

### Copy outside the dashboard
- The report email footers told readers to go to "Settings → Notification
  settings". They now say "under Reports in the dashboard". This covers
  the web HTML and text renderers and the Go plain-text fallback. The Go
  change is copy only, plus its golden `.eml` and one test assertion.

## 5. Not done / follow-ups
- Nothing was checked in a browser. The Chrome bridge didn't respond, and
  Docker Desktop (Postgres and the API) stopped partway through, so the
  new layouts are verified by lint, tsc, tests and `next build` only.
  `getEnrollmentStatus`'s agent lookup was never run against a real DB.
- Nav badge counts come from the dashboard layout. They refresh on a full
  load or `router.refresh()`, not on every client-side navigation.
- `hasSwarm` in `lib/queries-docker-fleet.ts` no longer has callers; it
  was folded into `getNavCounts`.
- With hosts present but no snapshot yet, the Vulnerabilities page's
  empty state still reads "No open vulnerabilities".
- A true risk trend needs a daily rollup table (`estate_daily`) written by
  a River job. Finding intervals are lossy for reopened findings, so the
  Overview shows no sparkline yet.
- Command-menu entity search (hosts and images by name through a search
  endpoint).
- URL-persisted state for client-mode `DataTable` (hosts and agents
  filters).
- Unifying the `FilterBar`+`Pager` tables (fleet vulns, packages, images)
  onto server-mode `DataTable`.
- Firewall coverage of listeners: there is no firewall data yet, so the
  Overview says "listening on all interfaces" rather than "exposed".
