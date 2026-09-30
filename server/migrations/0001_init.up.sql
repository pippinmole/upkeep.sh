-- Core schema for security-whatnot MVP.
-- Single-user-owns-hosts model (no orgs/teams yet).

CREATE TABLE users (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email         text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hosts (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hostname      text NOT NULL,
    label         text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_seen_at  timestamptz
);

-- One-time tokens shown in the dashboard for `docker run`/compose enrollment.
-- Consumed exactly once, then deleted.
CREATE TABLE enrollment_tokens (
    token         text PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);

-- Only a hash of the agent's bearer secret is ever stored server-side.
CREATE TABLE agent_credentials (
    host_id       uuid PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    secret_hash   text NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    rotated_at    timestamptz
);

CREATE TABLE snapshots (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id           uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    schema_version    int NOT NULL,
    collected_at      timestamptz NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    os_id             text NOT NULL,
    os_version_id     text NOT NULL,
    os_codename       text,
    reboot_required   boolean NOT NULL DEFAULT false,
    reboot_packages   text[] NOT NULL DEFAULT '{}',
    source_ip         inet
);
CREATE INDEX snapshots_host_id_received_at_idx ON snapshots(host_id, received_at DESC);

CREATE TABLE snapshot_packages (
    snapshot_id   uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name          text NOT NULL,
    version       text NOT NULL,
    arch          text NOT NULL,
    PRIMARY KEY (snapshot_id, name, arch)
);

CREATE TABLE listening_sockets (
    snapshot_id   uuid NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    proto         text NOT NULL,
    local_addr    text NOT NULL,
    port          int NOT NULL,
    pid           int,
    process_name  text,
    is_public     boolean NOT NULL DEFAULT false,
    PRIMARY KEY (snapshot_id, proto, local_addr, port)
);

-- Cached vulnerability data synced from OSV / Debian Security Tracker,
-- enriched with CISA KEV and FIRST EPSS.
CREATE TABLE vulnerabilities (
    id                  text PRIMARY KEY, -- e.g. "CVE-2024-1234"
    ecosystem           text NOT NULL,    -- "debian", "ubuntu"
    package_name        text NOT NULL,
    fixed_version       text,             -- NULL if unfixed upstream
    distro_release      text NOT NULL,    -- "bookworm", "jammy", ...
    summary             text,
    cvss_score          numeric,
    epss_score          numeric,
    epss_percentile     numeric,
    is_kev              boolean NOT NULL DEFAULT false,
    kev_added_at        date,
    source_updated_at   timestamptz,
    synced_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vulnerabilities_package_release_idx ON vulnerabilities(package_name, distro_release);

CREATE TABLE findings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    host_id         uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    kind            text NOT NULL, -- 'vulnerable_package' | 'public_port' | 'reboot_required'
    dedup_key       text NOT NULL, -- stable key for open/resolved tracking
    vulnerability_id text REFERENCES vulnerabilities(id),
    details         jsonb NOT NULL DEFAULT '{}',
    severity_rank   int NOT NULL DEFAULT 0, -- computed from KEV/EPSS, not raw CVSS
    status          text NOT NULL DEFAULT 'open', -- 'open' | 'resolved'
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz,
    UNIQUE (host_id, dedup_key)
);
CREATE INDEX findings_host_status_idx ON findings(host_id, status);

CREATE TABLE alert_rules (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind          text NOT NULL, -- matches findings.kind, or 'any'
    min_severity_rank int NOT NULL DEFAULT 0,
    digest        boolean NOT NULL DEFAULT false, -- batch into periodic digest vs immediate
    enabled       boolean NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_channels (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    alert_rule_id uuid REFERENCES alert_rules(id) ON DELETE CASCADE,
    kind          text NOT NULL, -- 'webhook' | 'email' | 'discord' | 'slack' | 'ntfy'
    config        jsonb NOT NULL, -- e.g. {"url": "...", "secret": "..."}
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alert_events (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id        uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    channel_id        uuid NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    event_type        text NOT NULL, -- 'opened' | 'resolved' | 'digest'
    sent_at           timestamptz,
    delivery_error    text,
    created_at        timestamptz NOT NULL DEFAULT now()
);
