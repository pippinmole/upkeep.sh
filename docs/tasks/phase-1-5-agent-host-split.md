# Phase 1.5 — agent/host split + Linux collector breadth
Design: [DOMAIN_MODEL.md §4](../DOMAIN_MODEL.md#4-domain-model-agents-hosts-os-families).
Today agent == host: enrollment creates a `hosts` row and the returned
`agent_id` *is* `hosts.id`. Independent of P1a–c (new tables key on
`host_id`, which survives the split).
- [x] Migration `0008_agent_host_split`: `agents`, re-key
      `agent_credentials` to `agent_id`, `agent_hosts` (mode
      `local`/`ssh`/`winrm`, one local per agent), `host_identities`,
      `hosts.os_family` + current OS summary columns + `duplicate_of`,
      `snapshots.agent_id`/`facts`/`uptime_seconds` (`collector_status`
      already landed in P1a), `enrollment_tokens.agent_name`.
      Backfill with `agents.id = hosts.id` so deployed agents'
      `credentials.json` keeps working unchanged.
- [x] Enrollment creates an agent, not a host; host upserted on first push
      by identity (`/etc/machine-id`), so an agent reinstall reattaches to
      the existing host instead of duplicating it. Duplicate-identity
      flagging: Q12 resolved by recommendation (`hosts.duplicate_of`,
      never auto-merged). Rules and "active" in PROTOCOL.md "Host
      resolution".
- [x] Payload `agent` + `host` blocks (ref, identity, hostname refreshed
      every push, `os_family`) and per-collector status; payloads without
      a host block keep mapping to the agent's local host. Shipped within
      `schema_version: 1` (additive), so no v2 was needed. Ingest keeps
      `hosts.hostname` and the OS summary current from the newest
      snapshot.
- [x] Dashboard host management for the split (migration 0011, `mgmt_*`
      SQL functions + server actions): merge a flagged duplicate into its
      original / "not a duplicate", revoke an agent, request a credential
      rotation, rename / archive / delete a host, detach a host from an
      inactive agent. Rules in DOMAIN_MODEL §4.3 "Management".
- [ ] Agent/host reporting gaps: ~~`hosts.arch`~~ (done: agent `arch`
      collector → `os.arch`, `snapshots.arch`, `hosts.arch`);
      `hosts.os_build` is never written (only meaningful for the
      Windows/macOS agents); the production image build needs
      `--build-arg VERSION=...` so `agent.version` isn't `dev`.
- [x] Dashboard **Agents** page lists collectors (name, status online /
      stale / revoked / never connected, version, platform, host count,
      vuln pills, last seen) with their hosts as expandable sub-rows (OS,
      mode, last collected, findings, "Possible duplicate"), on the new
      shared `DataTable` (Q11). Optional agent name in the Register dialog.
- [x] Standalone **Hosts** list (`/dashboard/hosts`, DataTable: host /
      label, OS, collecting agents, open findings + severity/KEV, last
      seen, duplicate / archived / merged badges, State facet). Sidebar
      has Hosts and Agents; "Add host" and "Register agent" share one
      dialog (Q15).
- [x] Linux collectors (file/procfs reads only, per-collector status,
      capped with a `truncated` flag): uptime, arch, UDP listeners,
      systemd services (unit files + `*.wants` + `/proc/*/cgroup`, no
      D-Bus), local users (`/etc/passwd`/`/etc/group`), processes on
      deleted libraries (`/proc/*/maps`), unattended-upgrades config +
      last apt update (hostname + machine-id landed with the split,
      running kernel in P1b). PROTOCOL.md "Linux breadth sections".
- [x] Migration `0010_host_facts`: `host_services` / `host_listeners`
      (TCP+UDP) / `host_users` on the validity-range pattern, per-(host,
      kind) set hashes in `host_fact_state`, never closed when the
      collector isn't ok (truncated = additive only);
      `snapshots.uptime_seconds` / `arch` / `facts` (validated
      `hostfacts.LinuxFacts`), `hosts.arch`. Host tabs Services /
      Listeners / Users (DataTable), overview System + Needs restart,
      header arch/uptime/needs-restart badges.
- [ ] Follow-ups to the Linux collectors: services `failed` state (needs
      D-Bus or journal parsing); `needs_restart` misses other users'
      processes without `CAP_SYS_PTRACE` (counted as unreadable); service
      / listener / user changes on the History tab; fleet "which hosts
      listen on port N" page (`host_listeners_port_open_idx` is ready);
      retire `listening_sockets` (and its unused `is_public`) once
      exposure (Phase 1.6) reads `host_listeners` instead.
- [x] Remote collection over SSH for Linux (Q3–Q5 decided 2026-09-27;
      migration 0012, PROTOCOL.md §4): "Add host" → "Reach it from an
      existing agent", `GET /v1/agent/config` + `POST /v1/agent/status`,
      read-only SFTP collection with an agent-held key, user-confirmed
      host key pinning. Verified end to end against an OpenSSH container.
- [ ] Remote follow-ups: a "Replace agent" option at enrollment (new
      agent takes over the old one's remote hosts, dashboard lists hosts
      still needing its new public key); editing a remote host's address /
      port / user (today: delete and re-add); per-host status on the
      host's own pages (today: Hosts list badge + dialog); listeners and
      deleted-library facts for remote hosts (need walking remote /proc,
      slow over SFTP); collecting several targets in parallel; WinRM.
- [ ] Faster setup feedback for remote hosts (post-MVP): agent polls
      config every ~10s while any target is unconfirmed or failing (60s
      otherwise); a "Try again" button that clears a target's backoff;
      surface failed collectors (e.g. unreadable dpkg status) in the
      setup dialog instead of showing "Connected".
