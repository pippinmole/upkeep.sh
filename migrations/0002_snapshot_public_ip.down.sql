ALTER TABLE snapshots
    DROP COLUMN IF EXISTS public_ipv4,
    DROP COLUMN IF EXISTS public_ipv6;
