# Machines Home Page and Top Bar Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the sidebar and the Overview with a Tailscale-style top bar and an alphabetical Machines list (vulnerability count pills per machine, "⋯" row menu), styled in a new "Persimmon" palette in light and dark.

**Architecture:** Web-only (Next.js App Router in `web/`). Server components fetch through `pool.query` helpers in `web/src/lib/`, one round trip per concern. Pure helpers (status, filters, active tab) live beside the queries and are unit-tested with `bun test`. Query modules are tested against a fake pool, as in `web/src/lib/queries-mcp-activity.test.ts`. Client components handle filtering, menus and copy.

**Tech Stack:** Next.js 16.3 (read `web/AGENTS.md` and `web/node_modules/next/dist/docs/` before writing Next code), React 19 with the React Compiler, Tailwind 4 (tokens in `web/src/app/globals.css`), radix-ui and shadcn components in `web/src/components/ui/`, lucide-react, `pg`, bun test, oxlint and oxfmt.

**Spec:** `docs/superpowers/specs/2026-11-05-machines-home-and-top-bar-design.md`

## Global Constraints

- No Go server, API or migration changes. Routes keep `/dashboard/hosts/...`; only UI copy says "Machine(s)".
- Every query takes `workspaceId` from `requireViewer()`. Never read a global or first workspace in new code. The workspace name comes from `workspaces.name`.
- Host-package and container-image vulnerability counts are never summed into one number (`docs/DOMAIN_MODEL.md` §3.6).
- `--primary` (buttons) stays neutral ink. The persimmon accent is only for the active tab, focus ring and links. Severity uses `--sev-*`.
- The Machines list is always sorted by hostname, case-insensitive, then by id. There is no sort control.
- Copy uses "machine" and "workspace", never "server" or "install".
- Text contrast meets WCAG AA in both themes. Every count uses `tabular-nums`.
- Skills in `web/.claude/skills/`: use **frontend-design** while styling components, **vercel-composition-patterns** for the top bar and machine-row kit, **vercel-react-best-practices** for data fetching, and **web-design-guidelines** in Task 8's review.
- Verify locally, since CI is unavailable. In `web/`, run `bun run typecheck && bun run lint && bun test && bun run build`. Use Conventional Commits with the `web` scope, and never `--no-verify`.

## Review Focus

1. **The row menu inside a clickable row.** Opening "⋯", choosing an item or closing a dialog must not navigate to the machine. The row link is a stretched `::after` link on the name, never an `<a>` wrapping the menu (Task 6, browser check).
2. **A machine with no agent rows**, such as after every agent was detached: status is `never`, and the collector label is `null`, never "undefined" (Task 4 test).
3. **Junk in the URL**, such as `?status=bogus&os=` or repeated keys: unknown values are ignored and the page renders unfiltered (Task 5 test).
4. **Search on missing fields:** a machine with a null OS, IP or label must not throw and must still match by hostname. A search on an IP fragment like `10.0.1` matches (Task 5 test).
5. **Read-only members:** the menu shows only Copy and Export, and "Add machine" is hidden (Task 6, browser check signed in as a member).

---

## File Structure

| File | Responsibility |
|---|---|
| `web/src/app/globals.css` | Persimmon tokens, light and dark; `--topbar*` tokens; sidebar tokens removed (Task 7) |
| `web/src/components/layout/nav-config.ts` | **Rewritten:** `tabs`, `moreLinks`, `isTabActive` |
| `web/src/components/layout/nav-config.test.ts` | Tests for `isTabActive` |
| `web/src/lib/queries-nav.ts` | **Rewritten:** `getTopBarData` (firing alerts, swarm, workspace name) |
| `web/src/lib/queries-nav.test.ts` | Fake-pool test |
| `web/src/components/layout/top-bar.tsx` | Server-rendered shell: wordmark, workspace, tabs, right cluster |
| `web/src/components/layout/top-bar-tabs.tsx` | Client: active-tab underline (needs `usePathname`) |
| `web/src/components/layout/user-menu.tsx` | Client: avatar dropdown (account, theme, log out); replaces `nav-user.tsx` |
| `web/src/lib/machines.ts` | Pure helpers: `machineStatus`, `collectorLabel`, `parseMachineFilters`, `filterMachines`, `summarizeMachines` |
| `web/src/lib/machines.test.ts` | Tests for the above |
| `web/src/lib/queries-machines.ts` | `getMachines(workspaceId)` |
| `web/src/lib/queries-machines.test.ts` | Fake-pool test |
| `web/src/components/machines/*` | `machine-list.tsx`, `machine-row.tsx`, `count-pills.tsx`, `machine-toolbar.tsx`, `machine-row-menu.tsx`, `machines-empty.tsx` |
| `web/src/app/dashboard/page.tsx` | **Rewritten:** the Machines page |
| `web/src/app/dashboard/layout.tsx` | Top bar instead of `SidebarProvider` + `AppSidebar` + `Header` |

---

### Task 1: Persimmon theme tokens

**Files:**
- Modify: `web/src/app/globals.css` (`:root` and `.dark` blocks, `@theme inline` mapping)

**Interfaces:**
- Produces: CSS variables `--topbar`, `--topbar-foreground`, `--topbar-muted` and `--brand` (persimmon), exposed to Tailwind as `bg-topbar`, `text-topbar-foreground`, `text-topbar-muted` and `bg-brand`/`text-brand`/`border-brand`. Existing names (`--background`, `--card`, `--primary`, `--sev-*`, `--success`, `--warning`, `--kev`, ...) keep their names with new values.

- [ ] **Step 1: Set the tokens.** Convert the spec's §5 table to OKLCH (keep the file's OKLCH style). Specifically:
  - `--ring` is `--brand`.
  - `--primary` is ink on paper in light and paper on ink in dark.
  - `--radius` is `0.5rem`.
  - `--sev-critical` is `#e5482b` in light and `#ff6a3d` in dark.
  - `--sev-high`/`-fg` and `--sev-medium`/`-fg` come from the spec's tint and text pairs.
  - Choose `--sev-low`, `--sev-unknown`, `--kev`, `--info` and `--accent-pro` in the same warm family.
  - Leave the `--sidebar-*` tokens until Task 7.
- [ ] **Step 2: Add the `@theme inline` entries** for `topbar`, `topbar-foreground`, `topbar-muted` and `brand`.
- [ ] **Step 3: Verify.** In `web/`, run `bun run build`; expected: succeeds. Then run `bun run dev`, open `/dashboard/vulnerabilities` in both themes, and check that the pages render with the warm palette and that body text passes AA (check with devtools' contrast picker).
- [ ] **Step 4: Commit** with `feat(web): Persimmon theme tokens`.

### Task 2: Nav model and top bar data

**Files:**
- Modify: `web/src/components/layout/nav-config.ts`, `web/src/components/layout/types.ts`, `web/src/lib/queries-nav.ts`, `web/src/components/layout/settings-sections.ts`
- Test: `web/src/components/layout/nav-config.test.ts`, `web/src/lib/queries-nav.test.ts`

**Interfaces:**
- Produces:
  - `type NavTab = { title: string; url: string; icon: LucideIcon; keywords?: string[]; match: string[] }`. `match` lists the path prefixes that light the tab.
  - `const tabs: NavTab[]` in this order: Machines `/dashboard` (match `["/dashboard", "/dashboard/hosts"]`), Vulnerabilities `/dashboard/vulnerabilities`, Images `/dashboard/images`, Alerts `/dashboard/alerts`, Reports `/dashboard/reports`, Settings `/dashboard/settings` (match also `/dashboard/agents`).
  - `const moreLinks: (NavTab & { swarmOnly?: boolean })[]`: Packages, Swarm (`swarmOnly`) and Agents. Only the command menu shows these.
  - `function isTabActive(pathname: string, tab: NavTab): boolean`.
  - `type TopBarData = { workspaceName: string; firingAlerts: number; hasSwarm: boolean }` in `types.ts`. This replaces `NavCounts`, `NavBadgeKey`, `NavBadgeTone`, `NavGroup` and `NavItem`.
  - `getTopBarData(workspaceId: string): Promise<TopBarData>`, cached with React `cache` like today.
  - `settingsSections` gains `{ title: "Agents", url: "/dashboard/agents", icon: RadioTower, keywords: ["collectors", "enroll", "install"] }`.

- [ ] **Step 1: Write the failing tests.**

```ts
// nav-config.test.ts
test("Machines is active on home and on machine pages only", () => {
  const m = tabs[0];
  expect(isTabActive("/dashboard", m)).toBe(true);
  expect(isTabActive("/dashboard/hosts/abc/vulnerabilities", m)).toBe(true);
  expect(isTabActive("/dashboard/vulnerabilities", m)).toBe(false); // "/dashboard" must match exactly
});
test("Settings is active under settings and agents", () => {
  const s = tabs.find((t) => t.title === "Settings")!;
  expect(isTabActive("/dashboard/settings/members", s)).toBe(true);
  expect(isTabActive("/dashboard/agents", s)).toBe(true);
  expect(isTabActive("/dashboard/settingsx", s)).toBe(false);
});
test("tab order", () => {
  expect(tabs.map((t) => t.title)).toEqual(["Machines", "Vulnerabilities", "Images", "Alerts", "Reports", "Settings"]);
});

// queries-nav.test.ts: fake pool via mock.module("./db"), as in queries-mcp-activity.test.ts
test("binds the workspace and maps the row", async () => {
  rows = [{ workspace_name: "Acme", firing_alerts: "3", has_swarm: true }];
  expect(await getTopBarData(WS)).toEqual({ workspaceName: "Acme", firingAlerts: 3, hasSwarm: true });
  expect(calls[0].params).toEqual([WS]);
  expect(calls[0].sql).toContain("FROM workspaces");
});
test("missing row falls back to zeros and an empty name", async () => {
  rows = [];
  expect(await getTopBarData(WS)).toEqual({ workspaceName: "", firingAlerts: 0, hasSwarm: false });
});
```

- [ ] **Step 2: Run the tests to confirm they fail.** Run `bun test src/components/layout/nav-config.test.ts src/lib/queries-nav.test.ts`. Expected: FAIL (`tabs` and `getTopBarData` are not exported).
- [ ] **Step 3: Implement.** `isTabActive` checks that the pathname equals the prefix or starts with `prefix + "/"`. The exception is `/dashboard`, which matches only exactly. `getTopBarData` keeps today's `firing_alerts` and `has_swarm` subqueries and adds `(SELECT name FROM workspaces WHERE id = $1) AS workspace_name`. Delete the `vulns_urgent`, `stale_hosts` and `stale_agents` subqueries. Fix the callers that break: `command-menu.tsx` builds its "Pages" group from `tabs` plus `moreLinks` (filtering `swarmOnly` by `hasSwarm`), and drops the `useSidebar`/`toggleSidebar` action and its ⌘B item. Delete `navGroupsFor` and `visibleNavConfig`.
- [ ] **Step 4: Run the tests to confirm they pass.** Run the same command; expected: PASS. Typecheck errors in `app-sidebar.tsx` and `nav-group.tsx` are expected until Task 3.
- [ ] **Step 5: Commit** with `feat(web): tab nav model and top bar data`.

### Task 3: Top bar replaces the sidebar

**Files:**
- Create: `web/src/components/layout/top-bar.tsx`, `top-bar-tabs.tsx`, `user-menu.tsx`
- Modify: `web/src/app/dashboard/layout.tsx`, `web/src/app/dashboard/settings/settings-nav.tsx` (plain links with the same look; no `Sidebar*` primitives)
- Delete: `web/src/components/layout/app-sidebar.tsx`, `header.tsx`, `nav-group.tsx`, `nav-settings.tsx`, `nav-user.tsx` (move its log-out and account items into `user-menu.tsx` first)

**Interfaces:**
- Consumes: `tabs` and `isTabActive` from `nav-config.ts`, `getTopBarData` and `TopBarData` (Task 2), and the existing `Search`, `CommandMenu`, `ThemeSwitch` logic and `LogOutButton`.
- Produces: `<TopBar data={TopBarData} user={User} />`, a server component.

- [ ] **Step 1: Build `TopBar`.** It is a `bg-topbar text-topbar-foreground` sticky header `h-12`, with these pieces:
  - **Left:** the wordmark "upkeep", then `/`, then the workspace name, truncated with `max-w-48 truncate` and a `title` attribute. The name sits in its own element with `data-slot="workspace"`, ready for the switcher.
  - **Middle:** `<TopBarTabs />`, a client component. Active tab text is `text-topbar-foreground` with `shadow-[inset_0_-2px_0_var(--brand)]`. Inactive tabs are `text-topbar-muted`, and the active tab gets `aria-current="page"`.
  - **Right:** `Search` restyled for the dark bar; a firing-alerts link, rendered only when `firingAlerts > 0`, showing a pulsing `--sev-critical` dot and the count, linking to `/dashboard/alerts?state=firing`; and `UserMenu`, an avatar with initials whose items are name and email, Account, Theme (light/dark/system radio), and Log out.
  - **Below `md`:** the tabs move to a second row, `overflow-x-auto`, with no scrollbar showing and the active tab scrolled into view on mount.
- [ ] **Step 2: Swap the layout.** `layout.tsx` renders `ViewerProvider`, then `TopBar`, then `<div id="content">{children}</div>`, then `CommandMenu hasSwarm`. Remove `SidebarProvider`, the `sidebar_state` cookie read and `getNavCounts`.
- [ ] **Step 3: Rebuild `SettingsNav`** with plain `Link`s and the same active rule, since it currently imports sidebar primitives that need `SidebarProvider`.
- [ ] **Step 4: Delete** the sidebar files listed above. Then run `grep -rn "components/ui/sidebar\|AppSidebar\|NavUser" src`; expected: no hits outside `components/ui/sidebar.tsx`.
- [ ] **Step 5: Verify.** In `web/`, run `bun run typecheck && bun run lint && bun test`; expected: all pass. Then run `bun run dev` and check that every tab navigates and lights correctly, that ⌘K opens, that the theme switch works, and that a 375px width shows the scrolling tab row with no horizontal page scroll.
- [ ] **Step 6: Commit** with `feat(web): top bar with tabs replaces the sidebar`.

### Task 4: `getMachines` query and status helpers

**Files:**
- Create: `web/src/lib/machines.ts` (types and `machineStatus`, `collectorLabel`), `web/src/lib/queries-machines.ts`
- Test: `web/src/lib/machines.test.ts`, `web/src/lib/queries-machines.test.ts`

**Interfaces:**
- Produces (in `machines.ts`):

```ts
export type AgentStatus = "online" | "stale" | "never" | "revoked";
export type MachineAgent = { id: string; name: string; mode: "local" | "ssh" | "winrm"; status: AgentStatus };
export type MachineStatus = "online" | "stale" | "never";
export type SeverityCounts = { critical: number; high: number; medium: number; low: number };
export type MachineRow = {
  id: string; hostname: string; label: string | null;
  osId: string | null; osVersion: string | null;
  ip: string | null;              // latest snapshot public_ipv4, else public_ipv6
  lastSeenAt: string | null; archivedAt: string | null; reported: boolean; // reported = any snapshot exists
  agents: MachineAgent[];         // sorted: non-revoked first, local, ssh, winrm, then name
  vulns: SeverityCounts & { kev: number };                         // host packages only
  images: { vulns: number; critical: number; kev: number; images: number }; // running images only
  duplicateOf: { id: string; hostname: string; label: string | null } | null;
  mergedInto: { id: string; hostname: string } | null;
  rebootRequired: boolean;
};
export function machineStatus(agents: MachineAgent[]): MachineStatus;
export function collectorLabel(agents: MachineAgent[]): { text: string; more: number } | null;
export function hasNoActiveAgent(agents: MachineAgent[]): boolean; // agents.length > 0 && all revoked
```

- Produces (in `queries-machines.ts`): `getMachines(workspaceId: string): Promise<MachineRow[]>`, covering archived machines too, so the page can offer "Show N archived".

- [ ] **Step 1: Write the failing tests.**

```ts
// machines.test.ts
const a = (status: AgentStatus, mode: MachineAgent["mode"] = "local", name = "a1"): MachineAgent => ({ id: name, name, mode, status });
test("status: any online wins", () => expect(machineStatus([a("stale"), a("online", "ssh")])).toBe("online"));
test("status: active but none online is stale", () => expect(machineStatus([a("never"), a("stale")])).toBe("stale"));
test("status: all revoked is stale with no active agent", () => {
  expect(machineStatus([a("revoked")])).toBe("stale");
  expect(hasNoActiveAgent([a("revoked")])).toBe(true);
});
test("status: only never-reported agents is never", () => expect(machineStatus([a("never")])).toBe("never"));
test("status: no agents is never, label null", () => {   // Review Focus 2
  expect(machineStatus([])).toBe("never");
  expect(collectorLabel([])).toBeNull();
});
test("label: local agent first, more counted", () => {
  expect(collectorLabel([a("online", "local", "x"), a("online", "ssh", "bastion")])).toEqual({ text: "Local agent", more: 1 });
});
test("label: remote names the agent", () => {
  expect(collectorLabel([a("online", "ssh", "bastion")])).toEqual({ text: "via bastion", more: 0 });
});
test("label: skips revoked when an active one exists", () => {
  expect(collectorLabel([a("revoked", "local", "old"), a("online", "ssh", "bastion")])).toEqual({ text: "via bastion", more: 0 });
});

// queries-machines.test.ts (fake pool)
test("scoped, sorted by hostname, host packages and running images apart", async () => {
  await getMachines(WS);
  expect(calls[0].params).toEqual([WS]);
  expect(calls[0].sql).toContain("WHERE h.workspace_id = $1");
  expect(calls[0].sql).toMatch(/ORDER BY lower\(h\.hostname\), h\.id/);
  expect(calls[0].sql).toContain("kind = 'vulnerable_package'");
  expect(calls[0].sql).toContain("kind = 'vulnerable_image'");
  expect(calls[0].sql).toContain("host_containers");
});
test("maps counts to numbers and nulls through", async () => {
  rows = [fixtureRow({ crit: "2", high: "0", img_vulns: "5", public_ipv4: null, public_ipv6: "2001:db8::1", agents: null })];
  const [m] = await getMachines(WS);
  expect(m.vulns.critical).toBe(2);
  expect(m.images.vulns).toBe(5);
  expect(m.ip).toBe("2001:db8::1");
  expect(m.agents).toEqual([]);
});
```

- [ ] **Step 2: Run the tests to confirm they fail.** Run `bun test src/lib/machines.test.ts src/lib/queries-machines.test.ts`. Expected: FAIL (the modules don't exist yet).
- [ ] **Step 3: Implement `machines.ts` helpers.** `collectorLabel` returns `"Local agent"` for `local` and `"via <name>"` otherwise. It picks the first agent with status other than `revoked` (falling back to the first agent), and `more` is the count of the other non-revoked agents.
- [ ] **Step 4: Implement `getMachines` in one SQL statement**, modeled on `getHosts` in `web/src/lib/queries.ts:278`. It needs these joins:
  - The agents lateral, reusing `AGENT_STATUS_SQL`.
  - A host-package lateral over `findings`, filtered by `host_id = h.id AND status = 'open' AND kind = 'vulnerable_package'`, with `count(*) FILTER (WHERE severity = 'critical')` and the same for `high`, `medium` and `low`, plus `is_kev`.
  - An image lateral over `findings f`, filtered by `f.host_id = h.id AND f.status = 'open' AND f.kind = 'vulnerable_image' AND EXISTS (SELECT 1 FROM host_containers c WHERE c.host_id = h.id AND c.image_id = f.image_id AND c.removed_at IS NULL)`. It selects `count(DISTINCT f.vuln_key)`, `count(DISTINCT f.vuln_key) FILTER (WHERE f.severity = 'critical')`, `count(DISTINCT f.vuln_key) FILTER (WHERE f.is_kev)`, and `count(DISTINCT (f.image_id, f.image_os, f.image_arch, f.image_variant))`.
  - A latest-snapshot lateral for `public_ipv4`, `public_ipv6`, `reboot_required` and `collected_at IS NOT NULL AS reported`.
  - The duplicate and merged joins from `getHosts`.
  - Finish with `ORDER BY lower(h.hostname), h.id`.
- [ ] **Step 5: Run the tests to confirm they pass.** Expected: PASS. If a migrated dev DB is up (`start-dev` skill), also run the SQL once by hand against it to catch column-name typos the fake pool can't.
- [ ] **Step 6: Commit** with `feat(web): getMachines query with per-severity counts`.

### Task 5: Filters, search and summary

**Files:**
- Modify: `web/src/lib/machines.ts`
- Test: `web/src/lib/machines.test.ts`

**Interfaces:**
- Consumes: `MachineRow` and `machineStatus` (Task 4), and `SearchParams`, `param` and `oneOf` from `web/src/lib/search-params.ts`.
- Produces:

```ts
export type MachineFilters = { q: string | null; status: MachineStatus | null; os: string | null; critical: boolean; kev: boolean; archived: boolean };
export function parseMachineFilters(sp: SearchParams): MachineFilters; // keys: q, status, os, critical=1, kev=1, archived=1
export function filterMachines(rows: MachineRow[], f: MachineFilters): MachineRow[];
export function summarizeMachines(rows: MachineRow[]): { machines: number; withCritical: number; archived: number };
export function hasCritical(m: MachineRow): boolean; // vulns.critical > 0 || images.critical > 0
export function hasKev(m: MachineRow): boolean;      // vulns.kev > 0 || images.kev > 0
```

- [ ] **Step 1: Write the failing tests.**

```ts
test("junk params are ignored", () => {            // Review Focus 3
  expect(parseMachineFilters({ status: "bogus", os: "", critical: "yes", q: ["web", "db"] }))
    .toEqual({ q: "web", status: null, os: null, critical: false, kev: false, archived: false });
});
test("search matches hostname, label, OS and IP fragments; nulls are safe", () => { // Review Focus 4
  const rows = [m({ hostname: "db-primary", ip: "10.0.1.12" }), m({ hostname: "edge", label: null, osId: null, ip: null })];
  expect(filterMachines(rows, f({ q: "10.0.1" })).map((r) => r.hostname)).toEqual(["db-primary"]);
  expect(filterMachines(rows, f({ q: "EDGE" })).map((r) => r.hostname)).toEqual(["edge"]);
});
test("critical filter counts packages or running images", () => {
  const rows = [m({ hostname: "a", vulns: { ...zero, critical: 1 } }), m({ hostname: "b", images: { ...noImg, critical: 2 } }), m({ hostname: "c" })];
  expect(filterMachines(rows, f({ critical: true })).map((r) => r.hostname)).toEqual(["a", "b"]);
});
test("archived hidden unless asked", () => {
  const rows = [m({ hostname: "a" }), m({ hostname: "b", archivedAt: "2026-01-01T00:00:00Z" })];
  expect(filterMachines(rows, f({})).map((r) => r.hostname)).toEqual(["a"]);
  expect(filterMachines(rows, f({ archived: true })).map((r) => r.hostname)).toEqual(["a", "b"]);
});
test("filtering keeps input order", () => { /* input b, a → output b, a: sort is the SQL's job */ });
test("summary ignores archived", () => {
  expect(summarizeMachines([m({ vulns: { ...zero, critical: 1 } }), m({ archivedAt: "2026-01-01T00:00:00Z" })]))
    .toEqual({ machines: 1, withCritical: 1, archived: 1 });
});
```

- [ ] **Step 2: Run the tests to confirm they fail.** Run `bun test src/lib/machines.test.ts`; expected: FAIL.
- [ ] **Step 3: Implement.** The search is a case-insensitive substring match over `hostname`, `label`, `osLabel(osId, osVersion)` from `web/src/lib/os.ts`, and `ip`. `os` filters on `osId`.
- [ ] **Step 4: Run the tests to confirm they pass.** Expected: PASS.
- [ ] **Step 5: Commit** with `feat(web): machine filters and summary`.

### Task 6: The Machines page

**Files:**
- Create: `web/src/components/machines/machine-list.tsx` (client), `machine-row.tsx`, `count-pills.tsx`, `machine-toolbar.tsx` (client), `machine-row-menu.tsx` (client), `machines-empty.tsx`
- Modify: `web/src/app/dashboard/page.tsx` (rewrite), `web/src/app/dashboard/hosts/host-row-actions.tsx` (export its dialogs for reuse), `web/src/app/dashboard/hosts/add-host-dialog.tsx` (button and title copy "Add machine")

**Interfaces:**
- Consumes: `getMachines`, `MachineRow`, `parseMachineFilters`, `filterMachines`, `summarizeMachines`, `machineStatus`, `collectorLabel` and `hasNoActiveAgent` (Tasks 4 and 5); `AddHostDialog`; `getCollectorAgents` and `getOnboardingState` (existing); `AutoRefresh` (move it from `components/overview/` to `components/auto-refresh.tsx`); `adminOnly` and `useViewer`; `manage-actions.ts`.
- Produces:
  - `<CountPills vulns={MachineRow["vulns"]} />`: critical/high/medium pills, with zero shown as a muted "0", plus an "N KEV" marker.
  - `<MachineRowMenu machine={MachineRow} />`.
  - `export function RenameDialog`, `ManageDialogs` (archive, unarchive, merge, dismiss, delete) from `host-row-actions.tsx`, now typed on `{ id, hostname, label, archivedAt, duplicateOf }` so both `HostListRow` and `MachineRow` fit.

- [ ] **Step 1: Write the page (server).** It awaits `requireViewer()`, then `Promise.all([getMachines, getCollectorAgents, getOnboardingState])`, and runs `parseMachineFilters(await searchParams)` (check the Next 16 `searchParams` Promise form in the bundled docs).
  - **Header:** h1 "Machines", the summary line, and `AddHostDialog`.
  - **Summary line copy:** "12 machines" when nothing is critical, "12 machines · 3 with critical vulnerabilities" otherwise, and "1 machine" in the singular.
  - **States:**
    - With no machines and no agent, render `<MachinesEmpty>`: one panel with the copy "Add your first machine", a short line about installing the agent or scanning over SSH, and `AddHostDialog`.
    - When no machine has reported, rows show "Waiting for first report" in place of the pills, plus `<AutoRefresh />`.
    - Otherwise pass the rows to `<MachineList rows filters />` and mount `<AutoRefresh everyMs={60_000} />`.
- [ ] **Step 2: `MachineToolbar` (client).** It holds a search input (debounced 200ms) and selects for Status and OS (the OS options come from the rows). It also has toggle chips for "Critical, packages or images" and "Known exploited". Every change writes the URL with `withParams` via `router.replace` (no scroll). "Clear" appears only when a filter is set.
- [ ] **Step 3: `MachineList` and `MachineRow`.** The list uses a `table` on `md+` and stacked cards below it. Columns follow spec §6.2:
  - **Machine:**
    - A status dot (`--success`, `--warning`, or `--muted-foreground` for never).
    - The label (if set, with the hostname in muted text), or the hostname.
    - The IP and the collector label with "+N".
    - Tags when they apply: "Possible duplicate", "Merged into X", "Reboot required" and "No active agent".
  - **OS:** `osLabel`.
  - **Last seen:** relative time, using the existing helper in `web/src/lib/time.ts`.
  - **Open vulnerabilities:**
    - `CountPills`, plus `+N in images` in muted text when `images.vulns > 0`. Its tooltip reads "N vulnerabilities in M running images · K critical".
    - "No open vulnerabilities" when both counts are 0.
  - **Menu.**

  The row link is the machine name's `<Link href={/dashboard/hosts/${id}}>` with `after:absolute after:inset-0` on a `relative` row. The menu trigger is `relative z-10` (Review Focus 1). A "Show N archived" / "Hide archived" button below the list toggles `archived=1`. When filters match nothing, show "No machines match" with a Clear button.
- [ ] **Step 4: `MachineRowMenu`.** It opens from a `MoreVertical` icon button labelled "Actions for <name>". Items in order:
  1. Copy hostname, and Copy IP when there is an IP. Both use `navigator.clipboard.writeText` and show an inline "Copied" state (check icon) for 1.5s, since the app has no toaster.
  2. Export vulnerabilities (CSV), a link to `/dashboard/hosts/${id}/vulnerabilities/export` with `download`.
  3. These items are admin-only (`useViewer().isAdmin`): Rename; then Merge into … and Not a duplicate, only when `duplicateOf`; then Archive or Unarchive; then a separator and Delete in `text-destructive`.

  The dialogs are the ones exported from `host-row-actions.tsx`, including the existing type-the-hostname delete confirmation.
- [ ] **Step 5: Verify.** In `web/`, run `bun run typecheck && bun run lint && bun test`; expected: pass. Then, with the dev stack and a test agent (`start-dev` skill), check in a browser:
  - **Ordering:** rows are alphabetical (try mixed case).
  - **Menu:** clicking "⋯", every menu item, and Escape never navigate (Review Focus 1).
  - **Filters:** filters survive reload, and `?status=bogus` renders unfiltered.
  - **Members:** signed in as a member, the menu has only Copy and Export, and Add machine is hidden (Review Focus 5).
  - **Delete:** delete still asks for the hostname.
  - **Layout:** at 375px, rows stack with no horizontal scroll.
  - **Themes:** light and dark both look right.
- [ ] **Step 6: Commit** with `feat(web): Machines home page`.

### Task 7: Redirects and removal of the Overview

**Files:**
- Modify: `web/src/app/dashboard/hosts/page.tsx` (becomes `redirect("/dashboard")`, preserving `searchParams`), `web/src/app/dashboard/attention/page.tsx` (becomes `redirect("/dashboard")`), `web/src/app/dashboard/hosts/[hostId]/layout.tsx:94` (breadcrumb `{ label: "Machines", href: "/dashboard" }`), and the links to `/dashboard/hosts` in `images/page.tsx`, `packages/page.tsx`, `vulnerabilities/page.tsx` and `settings/alert-rules/scope-fields.tsx` (point them at `/dashboard` and change "hosts" copy to "machines" in those link texts only). Also modify `web/src/app/globals.css` to remove the `--sidebar-*` tokens.
- Delete: in `web/src/components/overview/`, `cards.tsx`, `estate-card.tsx`, `first-run.tsx`, `getting-started.tsx`, `image-section.tsx`, `latest-report.tsx`, `needs-attention.tsx` and `urgent-vulns.tsx`. Also delete `web/src/app/dashboard/hosts/hosts-table.tsx`, `host-columns.tsx` and `table-cells.tsx`, plus `web/src/components/ui/sidebar.tsx` and `web/src/hooks/use-mobile.ts`. Before each deletion, run `grep -rn "<name>" src`; keep any file still imported elsewhere and note it in the commit body. Keep `web/src/lib/attention/`, which MCP tools use. Also keep `queries-overview*.ts` functions that other code uses; delete the ones whose only caller was the old Overview.
- Test: `web/src/lib/attention/attention.test.ts` stays green, since it is not affected.

- [ ] **Step 1: Write the redirects and update the links listed above.**
- [ ] **Step 2: Delete the dead files** after the grep check.
- [ ] **Step 3: Verify.** In `web/`, run `bun run typecheck && bun run lint && bun test && bun run build`; expected: all pass. `/dashboard/hosts?q=x` and `/dashboard/attention` both land on `/dashboard`.
- [ ] **Step 4: Commit** with `refactor(web): drop the Overview and the old hosts list`.

### Task 8: Design review pass

**Files:** whatever the review touches. This task adds no new features.

- [ ] **Step 1:** Run the **web-design-guidelines** skill over `web/src/components/layout/`, `web/src/components/machines/` and `web/src/app/dashboard/page.tsx`. Fix the findings about accessibility (focus rings on tabs and rows, `aria-label` on icon buttons, `aria-current`), forms and motion (`prefers-reduced-motion` for the firing pulse).
- [ ] **Step 2:** Run the **vercel-react-best-practices** skill over the same files. Check for no request waterfalls on the page (one `Promise.all`), no client components that only need to be server components, and stable keys.
- [ ] **Step 3:** Check in the browser, both themes, at 375px, 768px and 1440px, on Machines, a machine page, Vulnerabilities and Settings, since the other pages only inherit tokens and must not be broken.
- [ ] **Step 4: Verify.** In `web/`, run `bun run typecheck && bun run lint && bun test && bun run build`, then `hk check --all` from the repo root; expected: all pass.
- [ ] **Step 5: Commit** with `fix(web): design review fixes for the top bar and Machines`.

---

## Later slices (not in this plan; recorded so this one doesn't block them)

- **SaaS:** signup creating a workspace (`workspaces` row and an admin membership), a workspace switcher in the `data-slot="workspace"` spot, and `requireViewer()` resolving the workspace from the session instead of `getWorkspaceId()`'s "oldest workspace". Agent enrollment is already per-workspace.
- Redesign the machine page (step 2 of the user's flow), Vulnerabilities, Images, Alerts, Reports and Settings in the new style.
- Move the search and filters into SQL if machine counts outgrow client-side filtering.
