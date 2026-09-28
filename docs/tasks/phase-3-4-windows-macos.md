# Phase 3/4 — Windows and macOS agents (pending scope decision)
**Not started, and currently contradicts the [non-goals](non-goals.md)** — see
DOMAIN_MODEL.md open question Q1. Per-OS collector lists are in
[DOMAIN_MODEL.md §4.8](../DOMAIN_MODEL.md#48-per-os-collectors-whats-worth-sampling)
and the support matrix in §5.
- [ ] Decide Q1 (in scope? which first?) and update the [non-goals](non-goals.md),
      README, and ARCHITECTURE.md accordingly.
- [ ] Windows agent (native service): OS build/UBR, installed programs,
      KBs, Windows Update state, pending reboot, SCM services, listeners,
      Defender/firewall/BitLocker. Vuln matching approach: Q14.
- [ ] macOS agent (launchd daemon, signed pkg): SystemVersion, apps +
      pkgutil receipts, Homebrew, launchd services, SoftwareUpdate state,
      XProtect/ALF/FileVault. Vuln matching approach: Q14.
