-- Agent-self-reported, best-effort public IP addresses for a snapshot.
-- Distinct from snapshots.source_ip, which is the server-observed
-- TCP/proxy source address of the push connection (security-verification
-- purpose). Nullable: there is no sensible non-null default for "we don't
-- know this host's public IP" (unlike reboot_packages, which has '{}').
ALTER TABLE snapshots
    ADD COLUMN public_ipv4 inet,
    ADD COLUMN public_ipv6 inet;
