# Non-goals (don't build these for MVP)

Auto-patching, remote command execution, compliance reporting
(SOC2/CIS), Windows/macOS support, log analysis/SIEM features. These are
explicit product-scope exclusions, not just "later."

> Note (2026-09-26): Windows/macOS support and agent-initiated remote
> collection are under reconsideration in
> [DOMAIN_MODEL.md](../DOMAIN_MODEL.md) (open questions Q1, Q3). Q3 is
> decided (2026-09-27): agent-initiated remote collection over SSH is in
> scope (Linux, read-only SFTP). Until Q1 is decided, the rest stands. "Remote command execution" here means
> the *server* causing execution on a host, and stays excluded either
> way.
