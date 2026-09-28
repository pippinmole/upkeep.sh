# Email notifier: SMTP settings per channel, not platform config

Considered: one platform-wide SMTP server (operator config, e.g.
`SW_SMTP_*`) that every user's email channel sends through, versus each
channel carrying its own SMTP server.

**Decided: per channel.** The user enters host, port, security,
username/password and from/to in the channel form, like webhook and ntfy
settings; there is no platform SMTP config. Reasoning: self-hosters
already have a mail provider or relay, and mail sent from their own
domain and account lands better than mail from a shared sender; the
platform doesn't take on deliverability, sender-domain verification or
abuse handling for everyone's alerts; and it keeps the notifier framework
uniform (config + secrets per channel, no special-cased type). Cost: each
user has to configure SMTP themselves. A platform default could be added
later as an optional fallback without changing the channel schema.

Security choices that go with it: STARTTLS is the default and is
required when selected; certificates are always verified; credentials are
never sent over a connection without TLS unless the channel explicitly
turns on "Allow insecure authentication" (default off). Connections go
through `netguard`'s SMTP policy (ports 25/465/587/2525, public addresses
only) — see [ARCHITECTURE.md § Email (SMTP) channel](../ARCHITECTURE.md#email-smtp-channel).
