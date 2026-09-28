# Port exposure: host-side analysis, not an external scanner (MVP)

Considered (2026-09-27): a River job in the worker that TCP-probes an
agent's server-observed `snapshots.source_ip` on its listening ports,
versus deriving exposure from what the agent can read on the host.

**Decided: host-side analysis for the MVP; the external scanner is
deferred to Phase 2+.** The scanner's vantage point is the platform box,
not the internet. For self-hosters that is often wrong: agents pushing
over a private network (vSwitch, VPC, Tailscale/WireGuard) give a
private `source_ip`; firewall allowlists commonly let the user's own
admin box through, so "open from here" isn't "open to everyone"; an agent
on the platform box itself can't be probed from outside. A result that
is sometimes misleading costs trust in every other alert. It also brings
real infrastructure (scan jobs, rate limits, abuse controls) and the
"platform used to scan arbitrary targets" risk.

Instead: classify each listener from the host's own facts, namely
listeners, ufw configuration, and Docker published ports ([Phase
1.6](../tasks/phase-1-6-docker-exposure.md)). **ufw alone is not enough**: Docker publishes ports through
its own iptables rules, which are evaluated before ufw's, so
`ufw deny 5432` doesn't protect `ports: "5432:5432"`. That is the most
likely way a self-hoster's database becomes public, so Docker data is a
prerequisite, not an extra. The wording is "not protected by the host
firewall", never "public": provider firewalls (Hetzner Cloud and
similar) are invisible to the agent, and we expect users to run a host
firewall regardless. The scanner can come back later as a second
opinion, with the constraints in [Phase 2+](../tasks/phase-2-plus-deferred.md).
